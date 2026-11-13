using IapAuther.Logging;

namespace IapAuther.Auth;

internal static class TokenSourceFactory
{
    public static async Task<CachedTokenSource> CreateAsync(
        AuthConfig config,
        CancellationToken cancellationToken = default)
    {
        var log = config.Logger ?? new StderrLogger(AppLogLevel.Warn);
        var mode = config.Mode;

        ITokenSource inner;
        switch (mode)
        {
            case CredentialMode.Impersonate:
                if (string.IsNullOrWhiteSpace(config.ImpersonateServiceAccount))
                {
                    throw new AuthException("--credentials=impersonate requires --impersonate-service-account");
                }
                inner = await ImpersonatedTokenSource.CreateAsync(
                    config.ImpersonateServiceAccount,
                    config.Audience,
                    config.CredentialFile,
                    cancellationToken).ConfigureAwait(false);
                break;

            case CredentialMode.SignJwt:
                inner = await SignJwtTokenSource.CreateAsync(
                    config.ImpersonateServiceAccount,
                    config.Audience,
                    config.CredentialFile,
                    cancellationToken).ConfigureAwait(false);
                break;

            case CredentialMode.Adc:
                inner = await AdcTokenSource.CreateAsync(
                    config.Audience,
                    config.CredentialFile,
                    cancellationToken).ConfigureAwait(false);
                break;

            case CredentialMode.OAuth:
                inner = new OAuthTokenSource(
                    config.OAuthClientId ?? "",
                    config.OAuthClientSecret ?? "",
                    config.NoBrowser,
                    log);
                break;

            case CredentialMode.Auto:
                if (!string.IsNullOrWhiteSpace(config.ImpersonateServiceAccount))
                {
                    inner = await ImpersonatedTokenSource.CreateAsync(
                        config.ImpersonateServiceAccount,
                        config.Audience,
                        config.CredentialFile,
                        cancellationToken).ConfigureAwait(false);
                    break;
                }

                try
                {
                    inner = await AdcTokenSource.CreateAsync(
                        config.Audience,
                        config.CredentialFile,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (UserCredentialNotSupportedException ex)
                {
                    log.Info(
                        "ADC holds user credentials which cannot mint ID tokens for an arbitrary audience; falling back to desktop OAuth flow",
                        ("adc_error", ex.Message));
                    try
                    {
                        inner = new OAuthTokenSource(
                            config.OAuthClientId ?? "",
                            config.OAuthClientSecret ?? "",
                            config.NoBrowser,
                            log);
                    }
                    catch (AuthException oauthEx)
                    {
                        throw new AuthException(
                            "No usable credentials: run 'gcloud auth application-default login' with a service account, " +
                            "configure --impersonate-service-account, use --credentials=signjwt, or set " +
                            $"IAP_AUTHER_OAUTH_CLIENT_ID / IAP_AUTHER_OAUTH_CLIENT_SECRET for --credentials=oauth ({oauthEx.Message})",
                            oauthEx);
                    }
                }
                break;

            default:
                throw new AuthException($"Unknown credential mode: {mode}");
        }

        return new CachedTokenSource(inner, config.RefreshMargin);
    }
}
