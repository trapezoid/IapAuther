using System.Diagnostics;
using System.Security.Cryptography;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Http;
using IapAuther.Logging;

namespace IapAuther.Auth;

internal sealed class OAuthTokenSource : ITokenSource, IDisposable
{
    private const string UserId = "user";

    private readonly string _clientId;
    private readonly bool _noBrowser;
    private readonly StderrLogger _logger;
    private readonly IRefreshTokenStore _store;
    private readonly Action<string>? _browserLauncher;
    private readonly PkceGoogleAuthorizationCodeFlow _flow;

    public OAuthTokenSource(
        string clientId,
        string clientSecret,
        bool noBrowser = false,
        StderrLogger? logger = null,
        IRefreshTokenStore? store = null,
        HttpMessageHandler? httpMessageHandler = null,
        Action<string>? browserLauncher = null)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new AuthException(
                "--credentials=oauth requires --oauth-client-id / --oauth-client-secret " +
                "(or IAP_AUTHER_OAUTH_CLIENT_ID / IAP_AUTHER_OAUTH_CLIENT_SECRET, or IAP_MCP_OAUTH_CLIENT_ID / IAP_MCP_OAUTH_CLIENT_SECRET). " +
                "Create a Desktop app OAuth client in the same project as the IAP resource; see https://cloud.google.com/iap/docs/authentication-howto");
        }

        _clientId = clientId;
        _noBrowser = noBrowser;
        _logger = logger ?? new StderrLogger(AppLogLevel.Warn);
        _store = store ?? new RefreshTokenStore(TokenStoreMode.Auto, logger: _logger);
        _browserLauncher = browserLauncher;

        var initializer = new GoogleAuthorizationCodeFlow.Initializer
        {
            ClientSecrets = new ClientSecrets
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
            },
            Scopes = ["openid", "email"],
            Prompt = "consent",
        };
        if (httpMessageHandler is not null)
        {
            initializer.HttpClientFactory = new HttpClientFromMessageHandlerFactory(_ =>
                new HttpClientFromMessageHandlerFactory.ConfiguredHttpMessageHandler(
                    httpMessageHandler,
                    performsAutomaticDecompression: false,
                    handlesRedirect: false));
        }

        _flow = new PkceGoogleAuthorizationCodeFlow(initializer);
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var storedRefresh = await _store.LoadAsync(_clientId, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(storedRefresh))
            {
                try
                {
                    return await ExchangeRefreshTokenAsync(storedRefresh, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.Warn("Stored refresh token rejected; re-running browser sign-in", ("error", ex.Message));
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not AuthException)
        {
            _logger.Debug("Could not read stored refresh token", ("error", ex.Message));
        }

        var (refreshToken, idToken) = await RunBrowserFlowAsync(cancellationToken).ConfigureAwait(false);
        await TrySaveRefreshTokenAsync(refreshToken, cancellationToken).ConfigureAwait(false);
        return idToken;
    }

    private async Task<string> ExchangeRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken)
    {
        TokenResponse response;
        try
        {
            response = await _flow.RefreshTokenAsync(UserId, refreshToken, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not AuthException && ex is not OperationCanceledException)
        {
            throw new AuthException($"Refreshing OAuth token failed: {ex.Message}", ex);
        }

        if (string.IsNullOrEmpty(response.IdToken))
        {
            throw new AuthException("Token refresh response contained no id_token.");
        }

        if (!string.IsNullOrEmpty(response.RefreshToken) &&
            !string.Equals(response.RefreshToken, refreshToken, StringComparison.Ordinal))
        {
            await TrySaveRefreshTokenAsync(response.RefreshToken, cancellationToken).ConfigureAwait(false);
        }

        return response.IdToken;
    }

    private async Task<(string RefreshToken, string IdToken)> RunBrowserFlowAsync(CancellationToken cancellationToken)
    {
        var codeReceiver = new SilentBrowserCodeReceiver(_noBrowser, _logger, _browserLauncher);
        var redirectUri = codeReceiver.RedirectUri;
        var codeRequest = _flow.CreateAuthorizationCodeRequest(redirectUri, out var codeVerifier);
        var expectedState = JwtUtils.EncodeBase64Url(RandomNumberGenerator.GetBytes(24));
        codeRequest.State = expectedState;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromMinutes(5));

        AuthorizationCodeResponseUrl callback;
        try
        {
            callback = await codeReceiver.ReceiveCodeAsync(codeRequest, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AuthException("Timed out waiting for browser sign-in.");
        }

        if (!string.Equals(callback.State, expectedState, StringComparison.Ordinal))
        {
            throw new AuthException("OAuth callback state mismatch.");
        }
        if (!string.IsNullOrEmpty(callback.Error))
        {
            throw new AuthException($"OAuth authorization failed: {callback.Error}");
        }
        if (string.IsNullOrEmpty(callback.Code))
        {
            throw new AuthException("OAuth callback did not contain an authorization code.");
        }

        TokenResponse tokenResponse;
        try
        {
            tokenResponse = await _flow
                .ExchangeCodeForTokenAsync(UserId, callback.Code, codeVerifier, redirectUri, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not AuthException && ex is not OperationCanceledException)
        {
            throw new AuthException($"Exchanging authorization code failed: {ex.Message}", ex);
        }

        if (string.IsNullOrEmpty(tokenResponse.IdToken))
        {
            throw new AuthException("OAuth token response contained no id_token.");
        }
        if (string.IsNullOrEmpty(tokenResponse.RefreshToken))
        {
            throw new AuthException("OAuth token response contained no refresh_token.");
        }

        return (tokenResponse.RefreshToken, tokenResponse.IdToken);
    }

    private async ValueTask TrySaveRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken)
    {
        try
        {
            await _store.SaveAsync(_clientId, refreshToken, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not AuthException)
        {
            _logger.Warn("Could not persist refresh token; you will be asked to sign in again next run", ("error", ex.Message));
        }
    }

    private sealed class SilentBrowserCodeReceiver : LocalServerCodeReceiver
    {
        private readonly bool _noBrowser;
        private readonly StderrLogger _logger;
        private readonly Action<string>? _browserLauncher;

        public SilentBrowserCodeReceiver(bool noBrowser, StderrLogger logger, Action<string>? browserLauncher)
        {
            _noBrowser = noBrowser;
            _logger = logger;
            _browserLauncher = browserLauncher;
        }

        protected override bool OpenBrowser(string url)
        {
            _logger.Info("Opening browser for Google sign-in", ("url", url));
            _logger.WriteLine("iap-auther: Google sign-in required.");
            if (!_noBrowser)
            {
                _logger.WriteLine($"Opening browser for Google sign-in. If it does not open, visit:\n{url}");
                if (_browserLauncher is not null)
                {
                    _browserLauncher(url);
                }
                else
                {
                    TryOpenBrowser(url);
                }
            }
            else
            {
                _logger.WriteLine($"Visit this URL to sign in:\n{url}");
            }

            // Always return true so --no-browser and headless environments keep waiting on the printed URL.
            return true;
        }
    }

    private static void TryOpenBrowser(string url)
    {
        try
        {
            var startInfo = CreateBrowserStartInfo(url);
            using var process = Process.Start(startInfo);
        }
        catch
        {
            // URL is already printed as fallback.
        }
    }

    internal static ProcessStartInfo CreateBrowserStartInfo(string url)
    {
        if (OperatingSystem.IsMacOS())
        {
            return CreateUnixDetachedStartInfo("open", url);
        }
        if (OperatingSystem.IsWindows())
        {
            return new ProcessStartInfo(url)
            {
                UseShellExecute = true,
                CreateNoWindow = true,
            };
        }
        return CreateUnixDetachedStartInfo("xdg-open", url);
    }

    internal static ProcessStartInfo CreateUnixDetachedStartInfo(string executable, string url)
    {
        // Redirect stdin/stdout/stderr to /dev/null before exec so browser launchers (e.g.
        // "Opening in existing browser session.") never pollute parent stdout/stderr or touch
        // MCP stdio, and never rely on parent pipes that could raise SIGPIPE on CLI exit.
        var startInfo = new ProcessStartInfo("/bin/sh")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add("exec \"$1\" \"$2\" </dev/null >/dev/null 2>&1");
        startInfo.ArgumentList.Add("sh");
        startInfo.ArgumentList.Add(executable);
        startInfo.ArgumentList.Add(url);
        return startInfo;
    }

    public void Dispose() => _flow.Dispose();
}
