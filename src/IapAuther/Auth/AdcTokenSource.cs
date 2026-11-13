using Google.Apis.Auth.OAuth2;

namespace IapAuther.Auth;

internal sealed class UserCredentialNotSupportedException : AuthException
{
    public UserCredentialNotSupportedException(string message) : base(message) { }
    public UserCredentialNotSupportedException(string message, Exception innerException) : base(message, innerException) { }
}

internal sealed class AdcTokenSource : ITokenSource
{
    private readonly GoogleCredential _credential;
    private readonly string _audience;

    private AdcTokenSource(GoogleCredential credential, string audience)
    {
        _credential = credential;
        _audience = audience;
    }

    public static async Task<AdcTokenSource> CreateAsync(
        string audience,
        string? credentialFile,
        CancellationToken cancellationToken)
    {
        var credential = await GoogleCredentialLoader.LoadAsync(credentialFile, cancellationToken)
            .ConfigureAwait(false);

        if (credential.UnderlyingCredential is UserCredential)
        {
            throw new UserCredentialNotSupportedException(
                "ADC holds end-user (authorized_user) credentials, which cannot mint OIDC ID tokens for an arbitrary audience.");
        }

        return new AdcTokenSource(credential, audience);
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var oidcToken = await _credential
                .GetOidcTokenAsync(OidcTokenOptions.FromTargetAudience(_audience), cancellationToken)
                .ConfigureAwait(false);
            return await oidcToken.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (NotSupportedException ex)
        {
            throw new UserCredentialNotSupportedException(
                $"ADC credential type '{_credential.UnderlyingCredential.GetType().Name}' cannot mint OIDC ID tokens: {ex.Message}",
                ex);
        }
        catch (Exception ex) when (ex is not AuthException && ex is not OperationCanceledException)
        {
            throw new AuthException($"Minting ID token from ADC failed: {ex.Message}", ex);
        }
    }
}
