using System.Text;
using IapAuther.Auth;
using IapAuther.Cli;
using IapAuther.Logging;

namespace IapAuther.Tests;

public sealed class RefreshTokenStoreTests : IDisposable
{
    private readonly string _tempDir;

    public RefreshTokenStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"iap-auther-store-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    private sealed class FakeOsStore : IRefreshTokenStore
    {
        private readonly Dictionary<string, string> _items = new(StringComparer.Ordinal);

        public string BackendName => "fake-os-store";

        public Func<string, Exception?>? OnLoad { get; set; }
        public Func<string, string, Exception?>? OnSave { get; set; }
        public Func<string, Exception?>? OnDelete { get; set; }

        public int LoadCalls { get; private set; }
        public int SaveCalls { get; private set; }
        public int DeleteCalls { get; private set; }

        public ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default)
        {
            LoadCalls++;
            var err = OnLoad?.Invoke(clientId);
            if (err is not null)
            {
                throw err;
            }
            return new ValueTask<string?>(_items.GetValueOrDefault(clientId));
        }

        public ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default)
        {
            SaveCalls++;
            var err = OnSave?.Invoke(clientId, refreshToken);
            if (err is not null)
            {
                throw err;
            }
            _items[clientId] = refreshToken;
            return ValueTask.CompletedTask;
        }

        public ValueTask DeleteAsync(string clientId, CancellationToken cancellationToken = default)
        {
            DeleteCalls++;
            var err = OnDelete?.Invoke(clientId);
            if (err is not null)
            {
                throw err;
            }
            _items.Remove(clientId);
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task AutoMode_SavesLoadsDeletesInOsStore_AndCleansLegacyFile()
    {
        var osStore = new FakeOsStore();
        var fileStore = new FileRefreshTokenStore(_tempDir);
        await fileStore.SaveAsync("client-1", "stale-legacy");
        Assert.True(File.Exists(fileStore.GetTokenPath("client-1")));

        using var errWriter = new StringWriter();
        var logger = new StderrLogger(AppLogLevel.Info, LogOutputMode.Stderr, errWriter);
        var store = new RefreshTokenStore(TokenStoreMode.Auto, osStore, fileStore, logger);

        await store.SaveAsync("client-1", "fresh-os-token");
        Assert.False(File.Exists(fileStore.GetTokenPath("client-1")));
        Assert.Equal("fresh-os-token", await store.LoadAsync("client-1"));

        await store.DeleteAsync("client-1");
        Assert.Null(await store.LoadAsync("client-1"));
        Assert.Equal(2, osStore.LoadCalls);
        Assert.Equal(1, osStore.SaveCalls);
        Assert.Equal(1, osStore.DeleteCalls);
    }

    [Fact]
    public async Task AutoMode_MigratesLegacyFileToOsStore_AndDeletesLegacyFile()
    {
        var osStore = new FakeOsStore();
        var fileStore = new FileRefreshTokenStore(_tempDir);
        await fileStore.SaveAsync("client-migrate", "legacy-rt-value");
        var legacyPath = fileStore.GetTokenPath("client-migrate");
        Assert.True(File.Exists(legacyPath));

        using var errWriter = new StringWriter();
        var logger = new StderrLogger(AppLogLevel.Info, LogOutputMode.Stderr, errWriter);
        var store = new RefreshTokenStore(TokenStoreMode.Auto, osStore, fileStore, logger);

        var loaded = await store.LoadAsync("client-migrate");
        Assert.Equal("legacy-rt-value", loaded);
        Assert.False(File.Exists(legacyPath));
        Assert.Equal("legacy-rt-value", await osStore.LoadAsync("client-migrate"));
        Assert.Contains("Migrated OAuth refresh token", errWriter.ToString());
    }

    [Fact]
    public async Task AutoMode_WhenOsStoreUnavailable_FallsBackToFileStoreAndWarnsOnce()
    {
        var osStore = new FakeOsStore
        {
            OnLoad = _ => new CredentialStoreUnavailableException("daemon unavailable"),
            OnSave = (_, _) => new CredentialStoreUnavailableException("daemon unavailable"),
        };
        var fileStore = new FileRefreshTokenStore(_tempDir);

        using var errWriter = new StringWriter();
        var logger = new StderrLogger(AppLogLevel.Warn, LogOutputMode.Stderr, errWriter);
        var store = new RefreshTokenStore(TokenStoreMode.Auto, osStore, fileStore, logger);

        await store.SaveAsync("client-fallback", "rt-on-disk");
        Assert.True(File.Exists(fileStore.GetTokenPath("client-fallback")));
        Assert.Equal("rt-on-disk", await store.LoadAsync("client-fallback"));
        Assert.Equal("rt-on-disk", await fileStore.LoadAsync("client-fallback"));

        var stderr = errWriter.ToString();
        var warningCount = stderr.Split("OS credential store unavailable", StringSplitOptions.None).Length - 1;
        Assert.Equal(1, warningCount);
    }

    [Fact]
    public async Task AutoMode_MigrationWhenOsSaveFails_KeepsLegacyFileAndReturnsToken()
    {
        var osStore = new FakeOsStore
        {
            OnSave = (_, _) => new CredentialStoreUnavailableException("keyring locked"),
        };
        var fileStore = new FileRefreshTokenStore(_tempDir);
        await fileStore.SaveAsync("client-keep-legacy", "legacy-rt");
        var legacyPath = fileStore.GetTokenPath("client-keep-legacy");

        using var errWriter = new StringWriter();
        var logger = new StderrLogger(AppLogLevel.Warn, LogOutputMode.Stderr, errWriter);
        var store = new RefreshTokenStore(TokenStoreMode.Auto, osStore, fileStore, logger);

        var loaded = await store.LoadAsync("client-keep-legacy");
        Assert.Equal("legacy-rt", loaded);
        Assert.True(File.Exists(legacyPath));
        Assert.Contains("falling back to file token store", errWriter.ToString());
    }

    [Fact]
    public async Task OsMode_WhenUnavailable_ThrowsAuthExceptionAndIgnoresLegacyFile()
    {
        var fileStore = new FileRefreshTokenStore(_tempDir);
        await fileStore.SaveAsync("client-os", "legacy-only");
        var legacyPath = fileStore.GetTokenPath("client-os");

        // When OS store returns null, strict OS mode must not fall back to legacy file.
        var emptyOs = new FakeOsStore();
        var emptyStrictStore = new RefreshTokenStore(TokenStoreMode.Os, emptyOs, fileStore);
        Assert.Null(await emptyStrictStore.LoadAsync("client-os"));
        Assert.True(File.Exists(legacyPath));

        // When OS store is unavailable, strict OS mode throws AuthException on Load/Save/Delete.
        var brokenOs = new FakeOsStore
        {
            OnLoad = _ => new CredentialStoreUnavailableException("no session"),
            OnSave = (_, _) => new CredentialStoreUnavailableException("no session"),
            OnDelete = _ => new CredentialStoreUnavailableException("no session"),
        };
        var strictStore = new RefreshTokenStore(TokenStoreMode.Os, brokenOs, fileStore);

        await Assert.ThrowsAsync<AuthException>(() => strictStore.LoadAsync("client-os").AsTask());
        await Assert.ThrowsAsync<AuthException>(() => strictStore.SaveAsync("client-os", "new-rt").AsTask());
        await Assert.ThrowsAsync<AuthException>(() => strictStore.DeleteAsync("client-os").AsTask());
        Assert.Equal("legacy-only", await fileStore.LoadAsync("client-os"));
    }

    [Fact]
    public async Task FileMode_NeverCallsOsStore_AndDeletesCleanly()
    {
        var osStore = new FakeOsStore
        {
            OnLoad = _ => throw new InvalidOperationException("OS store should not be called"),
            OnSave = (_, _) => throw new InvalidOperationException("OS store should not be called"),
            OnDelete = _ => throw new InvalidOperationException("OS store should not be called"),
        };
        var fileStore = new FileRefreshTokenStore(_tempDir);
        var store = new RefreshTokenStore(TokenStoreMode.File, osStore, fileStore);

        await store.SaveAsync("client-file", "file-rt");
        Assert.Equal("file-rt", await store.LoadAsync("client-file"));
        await store.DeleteAsync("client-file");
        Assert.Null(await store.LoadAsync("client-file"));
    }

    [Fact]
    public async Task FileRefreshTokenStore_OnUnix_Enforces0600PermissionsEvenOnOverwrite()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var fileStore = new FileRefreshTokenStore(_tempDir);
        var path = fileStore.GetTokenPath("perm-client");
        await File.WriteAllTextAsync(path, "old-token", Encoding.UTF8);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        await fileStore.SaveAsync("perm-client", "new-token");

        var mode = File.GetUnixFileMode(path);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        Assert.Equal("new-token", await fileStore.LoadAsync("perm-client"));
    }

    [Fact]
    public async Task FileRefreshTokenStore_OnWindows_EncryptsWithDpapi()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var fileStore = new FileRefreshTokenStore(_tempDir);
        var path = fileStore.GetTokenPath("dpapi-client");
        Assert.EndsWith(".dpapi", path, StringComparison.Ordinal);

        await fileStore.SaveAsync("dpapi-client", "dpapi-secret-value-1");
        Assert.True(File.Exists(path));

        var rawBytes = await File.ReadAllBytesAsync(path);
        Assert.DoesNotContain("dpapi-secret-value-1", Encoding.UTF8.GetString(rawBytes));
        Assert.Equal("dpapi-secret-value-1", await fileStore.LoadAsync("dpapi-client"));

        await fileStore.SaveAsync("dpapi-client", "dpapi-secret-value-2");
        Assert.Equal("dpapi-secret-value-2", await fileStore.LoadAsync("dpapi-client"));

        await fileStore.DeleteAsync("dpapi-client");
        Assert.False(File.Exists(path));
        Assert.Null(await fileStore.LoadAsync("dpapi-client"));
    }

    [Fact]
    public async Task OAuthTokenSource_StrictOsStoreUnavailable_FailsBeforeOpeningBrowser()
    {
        var brokenOs = new FakeOsStore
        {
            OnLoad = _ => new CredentialStoreUnavailableException("keychain locked"),
        };
        var store = new RefreshTokenStore(TokenStoreMode.Os, brokenOs, new FileRefreshTokenStore(_tempDir));
        var browserCalled = false;

        using var source = new OAuthTokenSource(
            "client-id",
            "client-secret",
            store: store,
            browserLauncher: _ => browserCalled = true);

        await Assert.ThrowsAsync<AuthException>(() => source.GetTokenAsync().AsTask());
        Assert.False(browserCalled);
    }

    [Theory]
    [InlineData("auto", "auto")]
    [InlineData("AUTO", "auto")]
    [InlineData("os", "os")]
    [InlineData("keychain", "os")]
    [InlineData("keyring", "os")]
    [InlineData("native", "os")]
    [InlineData("file", "file")]
    public void TokenStoreModeExtensions_TryParse_AcceptsSupportedValues(string raw, string expectedCliString)
    {
        Assert.True(TokenStoreModeExtensions.TryParse(raw, out var parsed));
        Assert.Equal(expectedCliString, parsed.ToCliString());
    }

    [Fact]
    public async Task TokenCommand_RejectsInvalidTokenStoreMode()
    {
        using var outWriter = new StringWriter();
        using var errWriter = new StringWriter();

        var exitCode = await Program.RunAsync(
            ["token", "--token-store", "invalid-mode", "--audience", "aud"],
            outWriter,
            errWriter);

        Assert.Equal(ExitCodes.ConfigOrFatalError, exitCode);
        Assert.Equal(string.Empty, outWriter.ToString());
        Assert.Contains("unknown --token-store 'invalid-mode'", errWriter.ToString());
    }

    [Fact]
    public void SharedAuthOptions_TokenStoreEnvVar_ConfiguresTokenStore()
    {
        var orig = Environment.GetEnvironmentVariable("IAP_AUTHER_TOKEN_STORE");
        try
        {
            Environment.SetEnvironmentVariable("IAP_AUTHER_TOKEN_STORE", "os");
            var options = new SharedAuthOptions();
            var cmd = new System.CommandLine.Command("test");
            options.AddTo(cmd);

            var parsed = cmd.Parse(["--audience", "https://example.com"]);
            var ok = options.TryBuildConfig(parsed, null, TimeSpan.FromMinutes(5), out var config, out _, out var err);

            Assert.True(ok, err);
            Assert.NotNull(config);
            Assert.Equal(TokenStoreMode.Os, config!.TokenStore);
        }
        finally
        {
            Environment.SetEnvironmentVariable("IAP_AUTHER_TOKEN_STORE", orig);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
