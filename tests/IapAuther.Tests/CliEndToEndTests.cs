using System.Security.Cryptography;
using System.Text.Json;
using IapAuther.Auth;

namespace IapAuther.Tests;

public sealed class CliEndToEndTests : IDisposable
{
    private readonly string _tempKeyPath;

    public CliEndToEndTests()
    {
        _tempKeyPath = Path.Combine(Path.GetTempPath(), $"iap-auther-test-{Guid.NewGuid():N}.json");
        using var rsa = RSA.Create(2048);
        var pkcs8 = rsa.ExportPkcs8PrivateKeyPem();
        var saJson = JsonSerializer.Serialize(new
        {
            type = "service_account",
            project_id = "test-project",
            private_key_id = "test-key-id",
            private_key = pkcs8,
            client_email = "test-sa@test-project.iam.gserviceaccount.com",
            client_id = "1234567890",
            auth_uri = "https://accounts.google.com/o/oauth2/auth",
            token_uri = "https://oauth2.googleapis.com/token",
        });
        File.WriteAllText(_tempKeyPath, saJson);
    }

    [Fact]
    public async Task TokenCommand_SignJwtWithLocalServiceAccountFile_OutputsRawAndJsonAndHeader()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "token",
                "--credentials", "signjwt",
                "--credential-file", _tempKeyPath,
                "--format", "json",
                "https://my-mcp-xxxx.a.run.app/mcp",
            ],
            outWriter,
            errWriter);

        Assert.True(exitCode == ExitCodes.Ok, $"Expected exit 0, got {exitCode}. Stderr: {errWriter}");
        using var doc = JsonDocument.Parse(outWriter.ToString());
        var root = doc.RootElement;
        Assert.Equal("Bearer", root.GetProperty("token_type").GetString());
        Assert.Equal("Proxy-Authorization", root.GetProperty("header").GetString());
        Assert.Equal("https://my-mcp-xxxx.a.run.app/mcp", root.GetProperty("audience").GetString());
        Assert.Equal("signjwt", root.GetProperty("mode").GetString());

        var token = root.GetProperty("token").GetString()!;
        var claims = JwtUtils.ExtractClaims(token);
        Assert.Equal("test-sa@test-project.iam.gserviceaccount.com", claims.Issuer);
        Assert.Equal("https://my-mcp-xxxx.a.run.app/mcp", claims.Audience);
    }

    [Fact]
    public async Task TokenCommand_DefaultLogOutput_WritesLogsOnlyToStderrAndTokenOnlyToStdout()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "token",
                "--credentials", "signjwt",
                "--credential-file", _tempKeyPath,
                "--log-level", "info",
                "https://my-mcp-xxxx.a.run.app/mcp",
            ],
            outWriter,
            errWriter);

        Assert.Equal(ExitCodes.Ok, exitCode);
        var stdoutLines = outWriter.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var line = Assert.Single(stdoutLines);
        var claims = JwtUtils.ExtractClaims(line);
        Assert.Equal("https://my-mcp-xxxx.a.run.app/mcp", claims.Audience);

        var stderr = errWriter.ToString();
        Assert.Contains("level=INFO", stderr);
        Assert.Contains("No --audience given; derived from upstream URL", stderr);
    }

    [Fact]
    public async Task TokenCommand_LogOutputStdout_WritesLogsToStdoutAndLeavesStderrEmpty()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "token",
                "--credentials", "signjwt",
                "--credential-file", _tempKeyPath,
                "--log-level", "info",
                "--log-output", "stdout",
                "https://my-mcp-xxxx.a.run.app/mcp",
            ],
            outWriter,
            errWriter);

        Assert.Equal(ExitCodes.Ok, exitCode);
        Assert.Equal(string.Empty, errWriter.ToString());

        var stdoutLines = outWriter.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Equal(2, stdoutLines.Length);
        Assert.Contains("level=INFO", stdoutLines[0]);
        Assert.Contains("No --audience given; derived from upstream URL", stdoutLines[0]);

        var claims = JwtUtils.ExtractClaims(stdoutLines[1]);
        Assert.Equal("https://my-mcp-xxxx.a.run.app/mcp", claims.Audience);
    }

    [Fact]
    public async Task TokenCommand_LogOutputBoth_WritesLogsAndErrorsToBothStderrAndStdout()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "token",
                "--credentials", "signjwt",
                "--credential-file", _tempKeyPath,
                "--log-level", "info",
                "--log-output", "both",
                "https://my-mcp-xxxx.a.run.app/mcp",
            ],
            outWriter,
            errWriter);

        Assert.Equal(ExitCodes.Ok, exitCode);
        var stderr = errWriter.ToString();
        var stdout = outWriter.ToString();

        Assert.Contains("level=INFO", stderr);
        Assert.Contains("No --audience given; derived from upstream URL", stderr);
        Assert.Contains("level=INFO", stdout);
        Assert.Contains("No --audience given; derived from upstream URL", stdout);

        var stdoutLines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Equal(2, stdoutLines.Length);
        var claims = JwtUtils.ExtractClaims(stdoutLines[1]);
        Assert.Equal("https://my-mcp-xxxx.a.run.app/mcp", claims.Audience);

        // Also verify diagnostic config errors honor --log-output both.
        using var errOutWriter = new StringWriter();
        using var errErrWriter = new StringWriter();
        var failCode = await Program.RunAsync(["token", "--log-output", "both"], errOutWriter, errErrWriter);
        Assert.Equal(ExitCodes.ConfigOrFatalError, failCode);
        Assert.Contains("either --audience or an upstream URL is required", errOutWriter.ToString());
        Assert.Contains("either --audience or an upstream URL is required", errErrWriter.ToString());
    }

    [Fact]
    public async Task TokenCommand_LogOutputEnvVar_RoutesLogsToStdout()
    {
        var origEnv = Environment.GetEnvironmentVariable("IAP_AUTHER_LOG_OUTPUT");
        try
        {
            Environment.SetEnvironmentVariable("IAP_AUTHER_LOG_OUTPUT", "stdout");
            using var outWriter = new StringWriter();
            using var errWriter = new StringWriter();

            var exitCode = await Program.RunAsync(
                [
                    "token",
                    "--credentials", "signjwt",
                    "--credential-file", _tempKeyPath,
                    "--log-level", "info",
                    "https://my-mcp-xxxx.a.run.app/mcp",
                ],
                outWriter,
                errWriter);

            Assert.Equal(ExitCodes.Ok, exitCode);
            Assert.Equal(string.Empty, errWriter.ToString());
            Assert.Contains("level=INFO", outWriter.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("IAP_AUTHER_LOG_OUTPUT", origEnv);
        }
    }

    [Fact]
    public async Task TokenCommand_InvalidLogOutput_FailsWithConfigError()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            ["token", "--log-output", "file", "--audience", "aud"],
            outWriter,
            errWriter);

        Assert.Equal(ExitCodes.ConfigOrFatalError, exitCode);
        Assert.Equal(string.Empty, outWriter.ToString());
        Assert.Contains("unknown --log-output 'file'", errWriter.ToString());
    }

    [Fact]
    public async Task TokenCommand_RequiresAudienceOrUpstreamUrl()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(["token"], outWriter, errWriter);
        Assert.Equal(ExitCodes.ConfigOrFatalError, exitCode);
        Assert.Equal(string.Empty, outWriter.ToString());
        Assert.Contains("either --audience or an upstream URL is required", errWriter.ToString());
    }

    [Fact]
    public async Task McpProxyCommand_RejectsInvalidTransportMode()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "mcp-proxy",
                "--transport", "websocket",
                "https://mcp.example.com/mcp",
            ],
            outWriter,
            errWriter);
        Assert.Equal(ExitCodes.ConfigOrFatalError, exitCode);
        Assert.Equal(string.Empty, outWriter.ToString());
        Assert.Contains("invalid --transport value", errWriter.ToString());
    }

    [Fact]
    public async Task McpProxyCommand_RejectsInvalidLogOutput()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "mcp-proxy",
                "--log-output", "invalid",
                "https://mcp.example.com/mcp",
            ],
            outWriter,
            errWriter);
        Assert.Equal(ExitCodes.ConfigOrFatalError, exitCode);
        Assert.Equal(string.Empty, outWriter.ToString());
        Assert.Contains("unknown --log-output 'invalid'", errWriter.ToString());
    }

    [Fact]
    public async Task HeadersCommand_SignJwtWithExtraHeaders_OutputsSingleLineJsonAndRoutesLogsToStderr()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "headers",
                "--credentials", "signjwt",
                "--credential-file", _tempKeyPath,
                "--log-level", "info",
                "-H", "X-Tenant-Id: team-a",
                "--header", "Authorization: Bearer app+key=123",
                "-H", "x-tenant-id: team-b",
                "https://my-mcp-xxxx.a.run.app/mcp",
            ],
            outWriter,
            errWriter);

        Assert.True(exitCode == ExitCodes.Ok, $"Expected exit 0, got {exitCode}. Stderr: {errWriter}");
        var stdoutText = outWriter.ToString();
        var stdoutLines = stdoutText.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var jsonLine = Assert.Single(stdoutLines);
        Assert.Contains("Bearer app+key=123", jsonLine);

        using var doc = JsonDocument.Parse(jsonLine);
        var root = doc.RootElement;
        var proxyAuth = root.GetProperty("Proxy-Authorization").GetString()!;
        Assert.StartsWith("Bearer ", proxyAuth);
        var claims = JwtUtils.ExtractClaims(proxyAuth["Bearer ".Length..]);
        Assert.Equal("test-sa@test-project.iam.gserviceaccount.com", claims.Issuer);
        Assert.Equal("https://my-mcp-xxxx.a.run.app/mcp", claims.Audience);

        Assert.Equal("Bearer app+key=123", root.GetProperty("Authorization").GetString());
        Assert.Equal("team-b", root.GetProperty("x-tenant-id").GetString());
        Assert.False(root.TryGetProperty("X-Tenant-Id", out _));

        var stderr = errWriter.ToString();
        Assert.Contains("level=INFO", stderr);
        Assert.Contains("No --audience given; derived from upstream URL", stderr);
    }

    [Fact]
    public async Task HeadersCommand_EnvIndirection_ResolvesValueAndRejectsMissingVar()
    {
        const string envName = "IAP_AUTHER_TEST_HEADER_VALUE";
        var original = Environment.GetEnvironmentVariable(envName);
        try
        {
            Environment.SetEnvironmentVariable(envName, "Bearer secret-from-env");
            using var outWriter = new StringWriter();
            using var errWriter = new StringWriter();

            var okCode = await Program.RunAsync(
                [
                    "headers",
                    "--credentials", "signjwt",
                    "--credential-file", _tempKeyPath,
                    "-H", $"Authorization: env:{envName}",
                    "https://my-mcp-xxxx.a.run.app/mcp",
                ],
                outWriter,
                errWriter);

            Assert.Equal(ExitCodes.Ok, okCode);
            using var doc = JsonDocument.Parse(outWriter.ToString());
            Assert.Equal("Bearer secret-from-env", doc.RootElement.GetProperty("Authorization").GetString());

            Environment.SetEnvironmentVariable(envName, null);
            using var failOut = new StringWriter();
            using var failErr = new StringWriter();
            var failCode = await Program.RunAsync(
                [
                    "headers",
                    "--credentials", "signjwt",
                    "--credential-file", _tempKeyPath,
                    "-H", $"Authorization: env:{envName}",
                    "https://my-mcp-xxxx.a.run.app/mcp",
                ],
                failOut,
                failErr);

            Assert.Equal(ExitCodes.ConfigOrFatalError, failCode);
            Assert.Equal(string.Empty, failOut.ToString());
            Assert.Contains($"env:{envName}", failErr.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable(envName, original);
        }
    }

    [Theory]
    [InlineData("MissingColon", "expected 'Name: Value'")]
    [InlineData(": no-name", "expected 'Name: Value'")]
    [InlineData("Bad Name: value", "invalid header name")]
    [InlineData("proxy-authorization: Bearer override", "cannot override 'Proxy-Authorization'")]
    [InlineData("X-Inject: line1\nline2", "invalid control characters")]
    [InlineData("X-EmptyEnv: env:", "empty 'env:' reference")]
    public async Task HeadersCommand_RejectsInvalidHeaders(string headerArg, string expectedError)
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            [
                "headers",
                "--credentials", "signjwt",
                "--credential-file", _tempKeyPath,
                "-H", headerArg,
                "https://my-mcp-xxxx.a.run.app/mcp",
            ],
            outWriter,
            errWriter);

        Assert.Equal(ExitCodes.ConfigOrFatalError, exitCode);
        Assert.Equal(string.Empty, outWriter.ToString());
        Assert.Contains(expectedError, errWriter.ToString());
    }

    public void Dispose()
    {
        if (File.Exists(_tempKeyPath))
        {
            File.Delete(_tempKeyPath);
        }
    }
}
