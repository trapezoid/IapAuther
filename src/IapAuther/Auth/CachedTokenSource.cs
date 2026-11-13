namespace IapAuther.Auth;

internal sealed class CachedTokenSource : ITokenSource
{
    private readonly ITokenSource _inner;
    private readonly TimeSpan _margin;
    private readonly Func<DateTimeOffset> _now;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    private string? _cachedToken;
    private DateTimeOffset _expiry;

    public CachedTokenSource(ITokenSource inner, TimeSpan margin, Func<DateTimeOffset>? now = null)
    {
        _inner = inner;
        _margin = margin;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!string.IsNullOrEmpty(_cachedToken) && _now() < _expiry - _margin)
            {
                return _cachedToken;
            }

            var token = await _inner.GetTokenAsync(cancellationToken).ConfigureAwait(false);
            DateTimeOffset expiry;
            try
            {
                expiry = JwtUtils.ExtractExpiry(token);
            }
            catch (FormatException ex)
            {
                throw new AuthException($"Credential source returned a malformed ID token: {ex.Message}", ex);
            }

            _cachedToken = token;
            _expiry = expiry;
            return token;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public void Invalidate()
    {
        _mutex.Wait();
        try
        {
            _cachedToken = null;
            _expiry = default;
        }
        finally
        {
            _mutex.Release();
        }
    }
}

internal class AuthException : Exception
{
    public AuthException(string message) : base(message) { }
    public AuthException(string message, Exception innerException) : base(message, innerException) { }
}
