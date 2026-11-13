using IapAuther.Logging;

namespace IapAuther.Auth;

internal sealed class RefreshTokenStore : IRefreshTokenStore
{
    private readonly TokenStoreMode _mode;
    private readonly IRefreshTokenStore? _osStore;
    private readonly FileRefreshTokenStore _fileStore;
    private readonly StderrLogger _logger;
    private int _fallbackLogged;

    public RefreshTokenStore(string baseDirectory)
        : this(TokenStoreMode.File, osStore: null, new FileRefreshTokenStore(baseDirectory), logger: null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
    }

    public RefreshTokenStore(
        TokenStoreMode mode = TokenStoreMode.Auto,
        string? baseDirectory = null,
        StderrLogger? logger = null)
        : this(
            mode,
            mode == TokenStoreMode.File ? null : CreatePlatformOsStore(),
            new FileRefreshTokenStore(baseDirectory),
            logger)
    {
    }

    internal RefreshTokenStore(
        TokenStoreMode mode,
        IRefreshTokenStore? osStore,
        FileRefreshTokenStore fileStore,
        StderrLogger? logger = null)
    {
        _mode = mode;
        _osStore = osStore;
        _fileStore = fileStore ?? throw new ArgumentNullException(nameof(fileStore));
        _logger = logger ?? new StderrLogger(AppLogLevel.Warn);
    }

    public string BackendName =>
        _mode == TokenStoreMode.File || _osStore is null
            ? _fileStore.BackendName
            : _osStore.BackendName;

    public string GetTokenPath(string clientId) => _fileStore.GetTokenPath(clientId);

    public string? Load(string clientId) =>
        LoadAsync(clientId).AsTask().GetAwaiter().GetResult();

    public void Save(string clientId, string refreshToken) =>
        SaveAsync(clientId, refreshToken).AsTask().GetAwaiter().GetResult();

    public void Delete(string clientId) =>
        DeleteAsync(clientId).AsTask().GetAwaiter().GetResult();

    public async ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        if (_mode == TokenStoreMode.File)
        {
            return await _fileStore.LoadAsync(clientId, cancellationToken).ConfigureAwait(false);
        }

        if (_osStore is null)
        {
            if (_mode == TokenStoreMode.Os)
            {
                throw new AuthException("No native OS credential store backend is available on this platform.");
            }
            LogFallbackOnce("none", "no native OS credential store backend is available on this platform");
            return await _fileStore.LoadAsync(clientId, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            var token = await _osStore.LoadAsync(clientId, cancellationToken).ConfigureAwait(false);
            if (token is not null)
            {
                return token;
            }
        }
        catch (CredentialStoreUnavailableException ex)
        {
            if (_mode == TokenStoreMode.Os)
            {
                throw new AuthException(
                    $"OS credential store ({_osStore.BackendName}) is unavailable: {ex.Message}",
                    ex);
            }

            LogFallbackOnce(_osStore.BackendName, ex.Message);
            return await _fileStore.LoadAsync(clientId, cancellationToken).ConfigureAwait(false);
        }

        if (_mode == TokenStoreMode.Os)
        {
            return null;
        }

        var legacyToken = await _fileStore.LoadAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(legacyToken))
        {
            try
            {
                await _osStore.SaveAsync(clientId, legacyToken, cancellationToken).ConfigureAwait(false);
                _logger.Info(
                    "Migrated OAuth refresh token from legacy file store to OS credential store",
                    ("backend", _osStore.BackendName));
                await TryDeleteLegacyFileAsync(clientId, cancellationToken).ConfigureAwait(false);
            }
            catch (CredentialStoreUnavailableException ex)
            {
                LogFallbackOnce(_osStore.BackendName, ex.Message);
            }
        }

        return legacyToken;
    }

    public async ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(refreshToken);

        if (_mode == TokenStoreMode.File)
        {
            await _fileStore.SaveAsync(clientId, refreshToken, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (_osStore is null)
        {
            if (_mode == TokenStoreMode.Os)
            {
                throw new AuthException("No native OS credential store backend is available on this platform.");
            }
            LogFallbackOnce("none", "no native OS credential store backend is available on this platform");
            await _fileStore.SaveAsync(clientId, refreshToken, cancellationToken).ConfigureAwait(false);
            return;
        }

        try
        {
            await _osStore.SaveAsync(clientId, refreshToken, cancellationToken).ConfigureAwait(false);
            if (_mode == TokenStoreMode.Auto)
            {
                await TryDeleteLegacyFileAsync(clientId, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (CredentialStoreUnavailableException ex)
        {
            if (_mode == TokenStoreMode.Os)
            {
                throw new AuthException(
                    $"OS credential store ({_osStore.BackendName}) is unavailable: {ex.Message}",
                    ex);
            }

            LogFallbackOnce(_osStore.BackendName, ex.Message);
            await _fileStore.SaveAsync(clientId, refreshToken, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        if (_mode != TokenStoreMode.File)
        {
            if (_osStore is null)
            {
                if (_mode == TokenStoreMode.Os)
                {
                    throw new AuthException("No native OS credential store backend is available on this platform.");
                }
            }
            else
            {
                try
                {
                    await _osStore.DeleteAsync(clientId, cancellationToken).ConfigureAwait(false);
                }
                catch (CredentialStoreUnavailableException ex)
                {
                    if (_mode == TokenStoreMode.Os)
                    {
                        throw new AuthException(
                            $"OS credential store ({_osStore.BackendName}) is unavailable: {ex.Message}",
                            ex);
                    }
                    LogFallbackOnce(_osStore.BackendName, ex.Message);
                }
            }
        }

        if (_mode != TokenStoreMode.Os)
        {
            await _fileStore.DeleteAsync(clientId, cancellationToken).ConfigureAwait(false);
        }
    }

    internal static IRefreshTokenStore? CreatePlatformOsStore()
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsCredentialStore();
        }
        if (OperatingSystem.IsMacOS())
        {
            return new MacOSKeychainStore();
        }
        if (OperatingSystem.IsLinux())
        {
            return new LinuxSecretServiceStore();
        }
        return null;
    }

    private async Task TryDeleteLegacyFileAsync(string clientId, CancellationToken cancellationToken)
    {
        try
        {
            await _fileStore.DeleteAsync(clientId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug("Could not remove legacy refresh token file after migration", ("error", ex.Message));
        }
    }

    private void LogFallbackOnce(string backend, string reason)
    {
        if (Interlocked.Exchange(ref _fallbackLogged, 1) == 0)
        {
            _logger.Warn(
                "OS credential store unavailable; falling back to file token store",
                ("backend", backend),
                ("fallback", _fileStore.BackendName),
                ("error", reason));
        }
    }
}
