using System.Net.Http.Headers;
using IapAuther.Iap;
using IapAuther.Logging;

namespace IapAuther.Auth;

internal sealed class IapAuthHandler : DelegatingHandler
{
    private readonly CachedTokenSource _source;
    private readonly string _audience;
    private readonly string? _downstreamAuth;
    private readonly StderrLogger _logger;

    public IapAuthHandler(
        CachedTokenSource source,
        string audience,
        string? downstreamAuth = null,
        StderrLogger? logger = null,
        HttpMessageHandler? innerHandler = null)
        : base(innerHandler ?? CreateDefaultInnerHandler())
    {
        _source = source;
        _audience = audience;
        _downstreamAuth = downstreamAuth;
        _logger = logger ?? new StderrLogger(AppLogLevel.Warn);
    }

    public static HttpClientHandler CreateDefaultInnerHandler() => new()
    {
        // Never follow redirects: a 302 to accounts.google.com is an auth failure signal.
        AllowAutoRedirect = false,
    };

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        byte[]? bodyBytes = null;
        string? contentType = null;
        if (request.Content is not null)
        {
            contentType = request.Content.Headers.ContentType?.ToString();
            bodyBytes = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        }

        var response = await SendAttemptAsync(request, bodyBytes, contentType, cancellationToken).ConfigureAwait(false);
        if (!IapClassifier.IsAuthFailure(response))
        {
            return response;
        }

        _logger.Debug(
            "Upstream IAP auth failure; refreshing token and retrying once",
            ("status", (int)response.StatusCode),
            ("iap_generated", IapClassifier.IsIapResponse(response)));

        response.Dispose();
        _source.Invalidate();

        response = await SendAttemptAsync(request, bodyBytes, contentType, cancellationToken).ConfigureAwait(false);
        if (IapClassifier.IsAuthFailure(response))
        {
            var msg = await IapClassifier.BuildActionableMessageAsync(response, _audience, cancellationToken)
                .ConfigureAwait(false);
            _logger.Error(msg);
        }

        return response;
    }

    private async Task<HttpResponseMessage> SendAttemptAsync(
        HttpRequestMessage original,
        byte[]? bodyBytes,
        string? contentType,
        CancellationToken cancellationToken)
    {
        using var cloned = CloneRequest(original, bodyBytes, contentType);

        string token;
        try
        {
            token = await _source.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new AuthException($"Obtaining IAP token failed: {ex.Message}", ex);
        }

        cloned.Headers.ProxyAuthorization = new AuthenticationHeaderValue("Bearer", token);
        if (!string.IsNullOrEmpty(_downstreamAuth))
        {
            cloned.Headers.TryAddWithoutValidation("Authorization", _downstreamAuth);
        }

        return await base.SendAsync(cloned, cancellationToken).ConfigureAwait(false);
    }

    private static HttpRequestMessage CloneRequest(
        HttpRequestMessage original,
        byte[]? bodyBytes,
        string? contentType)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri)
        {
            Version = original.Version,
            VersionPolicy = original.VersionPolicy,
        };

        foreach (var header in original.Headers)
        {
            if (string.Equals(header.Key, "Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (bodyBytes is not null)
        {
            var content = new ByteArrayContent(bodyBytes);
            if (original.Content is not null)
            {
                foreach (var header in original.Content.Headers)
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }
            if (!string.IsNullOrEmpty(contentType) && content.Headers.ContentType is null)
            {
                content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            }
            clone.Content = content;
        }

        return clone;
    }
}
