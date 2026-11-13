using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Web;
using IapAuther.Auth;
using IapAuther.Logging;

namespace IapAuther.Tests;

public sealed class OAuthTokenSourceTests : IDisposable
{
    private readonly string _tempDir;

    public OAuthTokenSourceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"iap-auther-oauth-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    private sealed class FakeTokenEndpointHandler : HttpMessageHandler
    {
        private readonly string _idToken;
        private readonly string _refreshToken;

        public FakeTokenEndpointHandler(string idToken, string refreshToken)
        {
            _idToken = idToken;
            _refreshToken = refreshToken;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var json = JsonSerializer.Serialize(new
            {
                id_token = _idToken,
                refresh_token = _refreshToken,
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class SignalingStringWriter : StringWriter
    {
        private readonly TaskCompletionSource<string> _authUrlTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<string> WaitForAuthUrlAsync() => _authUrlTcs.Task;

        public override void WriteLine(string? value)
        {
            base.WriteLine(value);
            if (value is null)
            {
                return;
            }
            foreach (var line in value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (line.StartsWith("https://accounts.google.com/o/oauth2/v2/auth?", StringComparison.Ordinal))
                {
                    _authUrlTcs.TrySetResult(line);
                }
            }
        }
    }

    [Fact]
    public async Task BrowserFlow_DefaultStderrLogger_WritesPromptsOnlyToStderr()
    {
        var expectedJwt = CachedTokenSourceTests.MakeJwt(DateTimeOffset.UtcNow.AddHours(1));
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();
        using var http = new HttpClient(new FakeTokenEndpointHandler(expectedJwt, "rt-123"));
        var logger = new StderrLogger(AppLogLevel.Info, LogOutputMode.Stderr, errWriter, outWriter);

        Task? callbackTask = null;
        using var source = new OAuthTokenSource(
            "client-id.apps.googleusercontent.com",
            "client-secret",
            noBrowser: false,
            logger: logger,
            store: new RefreshTokenStore(_tempDir),
            httpClient: http,
            browserLauncher: authUrl => callbackTask = TriggerLoopbackCallbackAsync(authUrl));

        var token = await source.GetTokenAsync();
        Assert.NotNull(callbackTask);
        await callbackTask!;

        Assert.Equal(expectedJwt, token);
        Assert.Equal(string.Empty, outWriter.ToString());

        var stderr = errWriter.ToString();
        Assert.Contains("iap-auther: Google sign-in required.", stderr);
        Assert.Contains("Opening browser for Google sign-in. If it does not open, visit:", stderr);
        Assert.Contains("https://accounts.google.com/o/oauth2/v2/auth?", stderr);
        Assert.Contains("level=INFO", stderr);
    }

    [Fact]
    public async Task BrowserFlow_LogOutputBoth_WritesPromptsToBothStderrAndStdout()
    {
        var expectedJwt = CachedTokenSourceTests.MakeJwt(DateTimeOffset.UtcNow.AddHours(1));
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();
        using var http = new HttpClient(new FakeTokenEndpointHandler(expectedJwt, "rt-456"));
        var logger = new StderrLogger(AppLogLevel.Info, LogOutputMode.Both, errWriter, outWriter);

        Task? callbackTask = null;
        using var source = new OAuthTokenSource(
            "client-id.apps.googleusercontent.com",
            "client-secret",
            noBrowser: false,
            logger: logger,
            store: new RefreshTokenStore(_tempDir),
            httpClient: http,
            browserLauncher: authUrl => callbackTask = TriggerLoopbackCallbackAsync(authUrl));

        var token = await source.GetTokenAsync();
        Assert.NotNull(callbackTask);
        await callbackTask!;

        Assert.Equal(expectedJwt, token);

        foreach (var text in new[] { errWriter.ToString(), outWriter.ToString() })
        {
            Assert.Contains("iap-auther: Google sign-in required.", text);
            Assert.Contains("Opening browser for Google sign-in. If it does not open, visit:", text);
            Assert.Contains("level=INFO", text);
        }
    }

    [Fact]
    public async Task BrowserFlow_NoBrowserLogOutputStdout_WritesPromptsOnlyToStdout()
    {
        var expectedJwt = CachedTokenSourceTests.MakeJwt(DateTimeOffset.UtcNow.AddHours(1));
        using var outWriter = new SignalingStringWriter();
        using var errWriter = new StringWriter();
        using var http = new HttpClient(new FakeTokenEndpointHandler(expectedJwt, "rt-789"));
        var logger = new StderrLogger(AppLogLevel.Warn, LogOutputMode.Stdout, errWriter, outWriter);

        using var source = new OAuthTokenSource(
            "client-id.apps.googleusercontent.com",
            "client-secret",
            noBrowser: true,
            logger: logger,
            store: new RefreshTokenStore(_tempDir),
            httpClient: http);

        var tokenTask = source.GetTokenAsync().AsTask();
        var authUrl = await outWriter.WaitForAuthUrlAsync().WaitAsync(TimeSpan.FromSeconds(5));
        await TriggerLoopbackCallbackAsync(authUrl);

        var token = await tokenTask;
        Assert.Equal(expectedJwt, token);
        Assert.Equal(string.Empty, errWriter.ToString());

        var stdout = outWriter.ToString();
        Assert.Contains("iap-auther: Google sign-in required.", stdout);
        Assert.Contains("Visit this URL to sign in:", stdout);
    }

    [Fact]
    public async Task UnixDetachedStartInfo_SuppressesChildStdoutStderrAndStdinAndPreservesUrl()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var markerPath = Path.Combine(_tempDir, "url-arg.txt");
        var scriptPath = Path.Combine(_tempDir, "fake-browser.sh");
        var script = $$"""
            #!/bin/sh
            stdin_data=$(cat)
            if [ -n "$stdin_data" ]; then
                echo "UNEXPECTED_STDIN:$stdin_data" >&2
                exit 1
            fi
            echo "Opening in existing browser session."
            echo "noisy gtk/dbus warning on stderr" >&2
            printf '%s' "$1" > '{{markerPath}}'
            """;
        File.WriteAllText(scriptPath, script);
        File.SetUnixFileMode(
            scriptPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var trickyUrl = "https://accounts.google.com/o/oauth2/v2/auth?client_id=123&state=a+b&weird=$(id);echo%20hi";
        var startInfo = OAuthTokenSource.CreateUnixDetachedStartInfo(scriptPath, trickyUrl);

        // Simulate a parent caller with stdout/stderr pipes and an open stdin stream (e.g. mcp-proxy or $(...)).
        // If stdin were inherited instead of redirected to /dev/null, `cat` would hang waiting on StandardInput.
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        startInfo.RedirectStandardInput = true;

        using var process = Process.Start(startInfo)!;
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        process.StandardInput.Close();
        var capturedStdout = await stdoutTask;
        var capturedStderr = await stderrTask;

        Assert.Equal(0, process.ExitCode);
        Assert.Equal(string.Empty, capturedStdout);
        Assert.Equal(string.Empty, capturedStderr);
        Assert.Equal(trickyUrl, await File.ReadAllTextAsync(markerPath));
    }

    [Fact]
    public void CreateBrowserStartInfo_DetachesOnUnix()
    {
        var url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=test";
        var startInfo = OAuthTokenSource.CreateBrowserStartInfo(url);

        if (OperatingSystem.IsWindows())
        {
            Assert.True(startInfo.UseShellExecute);
            Assert.Equal(url, startInfo.FileName);
            return;
        }

        Assert.False(startInfo.UseShellExecute);
        Assert.Equal("/bin/sh", startInfo.FileName);
        var expectedLauncher = OperatingSystem.IsMacOS() ? "open" : "xdg-open";
        Assert.Contains(expectedLauncher, startInfo.ArgumentList);
        Assert.Equal(url, startInfo.ArgumentList[^1]);
    }

    private static async Task TriggerLoopbackCallbackAsync(string authUrl)
    {
        var uri = new Uri(authUrl);
        var query = HttpUtility.ParseQueryString(uri.Query);
        var redirectUri = query["redirect_uri"]!;
        var state = query["state"]!;

        using var callbackClient = new HttpClient();
        using var resp = await callbackClient.GetAsync(
            $"{redirectUri}?code=test-auth-code&state={Uri.EscapeDataString(state)}");
        resp.EnsureSuccessStatusCode();
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
