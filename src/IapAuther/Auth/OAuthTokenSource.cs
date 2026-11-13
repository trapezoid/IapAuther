using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using IapAuther.Logging;

namespace IapAuther.Auth;

internal sealed class OAuthTokenSource : ITokenSource, IDisposable
{
    private const string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private const string TokenEndpoint = "https://oauth2.googleapis.com/token";

    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly bool _noBrowser;
    private readonly StderrLogger _logger;
    private readonly RefreshTokenStore _store;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly Action<string>? _browserLauncher;

    public OAuthTokenSource(
        string clientId,
        string clientSecret,
        bool noBrowser = false,
        StderrLogger? logger = null,
        RefreshTokenStore? store = null,
        HttpClient? httpClient = null,
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
        _clientSecret = clientSecret;
        _noBrowser = noBrowser;
        _logger = logger ?? new StderrLogger(AppLogLevel.Warn);
        _store = store ?? new RefreshTokenStore();
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _browserLauncher = browserLauncher;
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var storedRefresh = _store.Load(_clientId);
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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug("Could not read stored refresh token", ("error", ex.Message));
        }

        var (refreshToken, idToken) = await RunBrowserFlowAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _store.Save(_clientId, refreshToken);
        }
        catch (Exception ex)
        {
            _logger.Warn("Could not persist refresh token; you will be asked to sign in again next run", ("error", ex.Message));
        }

        return idToken;
    }

    private async Task<string> ExchangeRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = _clientId,
            ["client_secret"] = _clientSecret,
            ["refresh_token"] = refreshToken,
            ["grant_type"] = "refresh_token",
        });

        using var response = await _http.PostAsync(TokenEndpoint, content, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new AuthException($"Refreshing OAuth token failed (HTTP {(int)response.StatusCode}): {body}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("id_token", out var idProp) ||
            string.IsNullOrEmpty(idProp.GetString()))
        {
            throw new AuthException("Token refresh response contained no id_token.");
        }

        return idProp.GetString()!;
    }

    private async Task<(string RefreshToken, string IdToken)> RunBrowserFlowAsync(CancellationToken cancellationToken)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var redirectUri = $"http://127.0.0.1:{port}/callback";

        var state = GenerateRandomBase64Url(24);
        var codeVerifier = GenerateRandomBase64Url(32);
        var codeChallenge = JwtUtils.EncodeBase64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

        var query = HttpUtility.ParseQueryString(string.Empty);
        query["client_id"] = _clientId;
        query["redirect_uri"] = redirectUri;
        query["response_type"] = "code";
        query["scope"] = "openid email";
        query["access_type"] = "offline";
        query["prompt"] = "consent";
        query["state"] = state;
        query["code_challenge"] = codeChallenge;
        query["code_challenge_method"] = "S256";

        var authUrl = $"{AuthorizationEndpoint}?{query}";

        _logger.Info("Opening browser for Google sign-in", ("url", authUrl));
        _logger.WriteLine("iap-auther: Google sign-in required.");
        if (!_noBrowser)
        {
            _logger.WriteLine($"Opening browser for Google sign-in. If it does not open, visit:\n{authUrl}");
            if (_browserLauncher is not null)
            {
                _browserLauncher(authUrl);
            }
            else
            {
                TryOpenBrowser(authUrl);
            }
        }
        else
        {
            _logger.WriteLine($"Visit this URL to sign in:\n{authUrl}");
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromMinutes(5));

        string code;
        try
        {
            code = await WaitForCallbackCodeAsync(listener, state, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AuthException("Timed out waiting for browser sign-in.");
        }
        finally
        {
            listener.Stop();
        }

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = _clientId,
            ["client_secret"] = _clientSecret,
            ["code"] = code,
            ["code_verifier"] = codeVerifier,
            ["redirect_uri"] = redirectUri,
            ["grant_type"] = "authorization_code",
        });

        using var response = await _http.PostAsync(TokenEndpoint, form, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new AuthException($"Exchanging authorization code failed (HTTP {(int)response.StatusCode}): {body}");
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        var idToken = root.TryGetProperty("id_token", out var idProp) ? idProp.GetString() : null;
        var refreshToken = root.TryGetProperty("refresh_token", out var rtProp) ? rtProp.GetString() : null;

        if (string.IsNullOrEmpty(idToken))
        {
            throw new AuthException("OAuth token response contained no id_token.");
        }
        if (string.IsNullOrEmpty(refreshToken))
        {
            throw new AuthException("OAuth token response contained no refresh_token.");
        }

        return (refreshToken, idToken);
    }

    private static async Task<string> WaitForCallbackCodeAsync(
        TcpListener listener,
        string expectedState,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            await using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, leaveOpen: true);

            var requestLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(requestLine))
            {
                continue;
            }

            // Drain HTTP headers until blank line.
            while (true)
            {
                var headerLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrEmpty(headerLine))
                {
                    break;
                }
            }

            var parts = requestLine.Split(' ');
            var target = parts.Length >= 2 ? parts[1] : "/";
            var uri = new Uri($"http://127.0.0.1{target}");

            if (!string.Equals(uri.AbsolutePath, "/callback", StringComparison.Ordinal))
            {
                await WriteHttpResponseAsync(stream, 404, "Not Found", "Not Found", cancellationToken).ConfigureAwait(false);
                continue;
            }

            var query = HttpUtility.ParseQueryString(uri.Query);
            if (!string.Equals(query["state"], expectedState, StringComparison.Ordinal))
            {
                await WriteHttpResponseAsync(stream, 400, "Bad Request", "State mismatch.", cancellationToken).ConfigureAwait(false);
                throw new AuthException("OAuth callback state mismatch.");
            }

            var oauthError = query["error"];
            if (!string.IsNullOrEmpty(oauthError))
            {
                await WriteHttpResponseAsync(stream, 400, "Bad Request", $"Sign-in failed: {oauthError}. You can close this window.", cancellationToken).ConfigureAwait(false);
                throw new AuthException($"OAuth authorization failed: {oauthError}");
            }

            var code = query["code"];
            if (string.IsNullOrEmpty(code))
            {
                await WriteHttpResponseAsync(stream, 400, "Bad Request", "Missing authorization code.", cancellationToken).ConfigureAwait(false);
                throw new AuthException("OAuth callback did not contain an authorization code.");
            }

            await WriteHttpResponseAsync(stream, 200, "OK", "Signed in. You can close this window and return to your terminal.", cancellationToken).ConfigureAwait(false);
            return code;
        }
    }

    private static async Task WriteHttpResponseAsync(
        NetworkStream stream,
        int statusCode,
        string reason,
        string body,
        CancellationToken cancellationToken)
    {
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var header = $"HTTP/1.1 {statusCode} {reason}\r\n" +
                     "Content-Type: text/plain; charset=utf-8\r\n" +
                     $"Content-Length: {bodyBytes.Length}\r\n" +
                     "Connection: close\r\n\r\n";
        var headerBytes = Encoding.ASCII.GetBytes(header);
        await stream.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string GenerateRandomBase64Url(int byteLength)
    {
        var bytes = RandomNumberGenerator.GetBytes(byteLength);
        return JwtUtils.EncodeBase64Url(bytes);
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

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }
}
