using System.Net;
using System.Text;

namespace IapAuther.Iap;

internal static class IapClassifier
{
    public const string GeneratedResponseHeader = "X-Goog-Iap-Generated-Response";

    public static bool IsIapResponse(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues(GeneratedResponseHeader, out var values))
        {
            foreach (var v in values)
            {
                if (string.Equals(v.Trim(), "true", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        return false;
    }

    public static bool IsAuthFailure(HttpResponseMessage response)
    {
        switch (response.StatusCode)
        {
            case HttpStatusCode.Unauthorized:
                return true;
            case HttpStatusCode.Found:
            case HttpStatusCode.MovedPermanently:
            case HttpStatusCode.SeeOther:
            case HttpStatusCode.TemporaryRedirect:
                return IsGoogleSignInRedirect(response);
            default:
                return false;
        }
    }

    public static bool IsGoogleSignInRedirect(HttpResponseMessage response)
    {
        var location = response.Headers.Location;
        if (location is null && response.Headers.TryGetValues("Location", out var values))
        {
            var raw = values.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(raw) && Uri.TryCreate(raw, UriKind.RelativeOrAbsolute, out var parsed))
            {
                location = parsed;
            }
        }

        if (location is null || !location.IsAbsoluteUri)
        {
            return false;
        }

        return string.Equals(location.Host, "accounts.google.com", StringComparison.OrdinalIgnoreCase);
    }

    public static async Task<string> BuildActionableMessageAsync(
        HttpResponseMessage response,
        string audience,
        CancellationToken cancellationToken = default)
    {
        var body = await PeekBodyAsync(response, 4096, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.Unauthorized &&
            body.Contains("audience", StringComparison.OrdinalIgnoreCase))
        {
            return $"audience mismatch: token aud={audience} rejected by IAP. " +
                   "Managed direct Cloud Run IAP (the default today) rejects OIDC ID tokens entirely — use --credentials=signjwt. " +
                   "For custom-client / load-balancer IAP, pass --audience <NNN>.apps.googleusercontent.com (the IAP OAuth client ID)";
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return $"IAP rejected the token (aud={audience}): for managed direct Cloud Run IAP use --credentials=signjwt " +
                   "(it rejects OIDC ID tokens); otherwise verify the audience and that the token is a Google-issued OIDC ID token " +
                   $"(IAP said: {FirstLine(body)})";
        }

        if (response.StatusCode == HttpStatusCode.Forbidden && IsIapResponse(response))
        {
            return "permission denied: grant roles/iap.httpsResourceAccessor to the calling principal on the IAP resource";
        }

        if (IsAuthFailure(response))
        {
            return $"IAP redirected to Google sign-in (token absent or malformed); check credentials and --audience (current aud={audience})";
        }

        return $"upstream returned HTTP {(int)response.StatusCode}: {FirstLine(body)}";
    }

    private static async Task<string> PeekBodyAsync(
        HttpResponseMessage response,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        if (response.Content is null)
        {
            return string.Empty;
        }

        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var buffer = new byte[maxBytes];
        var totalRead = 0;
        while (totalRead < maxBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, maxBytes - totalRead), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            totalRead += read;
        }

        var prefix = buffer.AsSpan(0, totalRead).ToArray();
        var originalHeaders = response.Content.Headers;
        var rewrapped = new StreamContent(new PrefixedStream(prefix, stream));
        foreach (var header in originalHeaders)
        {
            rewrapped.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        response.Content = rewrapped;

        return Encoding.UTF8.GetString(prefix);
    }

    private static string FirstLine(string s)
    {
        s = s.Trim();
        var nl = s.IndexOf('\n');
        if (nl >= 0)
        {
            s = s[..nl].TrimEnd('\r');
        }
        if (s.Length > 200)
        {
            s = s[..200] + "...";
        }
        return string.IsNullOrEmpty(s) ? "(empty body)" : s;
    }

    private sealed class PrefixedStream(byte[] prefix, Stream rest) : Stream
    {
        private int _offset;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (_offset < prefix.Length)
            {
                var toCopy = Math.Min(buffer.Length, prefix.Length - _offset);
                prefix.AsSpan(_offset, toCopy).CopyTo(buffer);
                _offset += toCopy;
                return toCopy;
            }
            return rest.Read(buffer);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_offset < prefix.Length)
            {
                var toCopy = Math.Min(buffer.Length, prefix.Length - _offset);
                prefix.AsSpan(_offset, toCopy).CopyTo(buffer.Span);
                _offset += toCopy;
                return ValueTask.FromResult(toCopy);
            }
            return rest.ReadAsync(buffer, cancellationToken);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                rest.Dispose();
            }
            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync() => rest.DisposeAsync();
    }
}
