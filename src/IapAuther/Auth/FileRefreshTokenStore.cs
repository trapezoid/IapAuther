using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace IapAuther.Auth;

internal sealed class FileRefreshTokenStore : IRefreshTokenStore
{
    private readonly string _directory;

    public FileRefreshTokenStore(string? baseDirectory = null)
    {
        _directory = !string.IsNullOrWhiteSpace(baseDirectory)
            ? baseDirectory
            : GetDefaultConfigDirectory();
    }

    public string BackendName => OperatingSystem.IsWindows() ? "file-dpapi" : "file-0600";

    public string DirectoryPath => _directory;

    public string GetTokenPath(string clientId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        var safeId = SanitizeFileName(clientId);
        var suffix = OperatingSystem.IsWindows() ? ".dpapi" : "";
        return Path.Combine(_directory, $"refresh-token-{safeId}{suffix}");
    }

    public ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new ValueTask<string?>(Load(clientId));
    }

    public ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Save(clientId, refreshToken);
        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Delete(clientId);
        return ValueTask.CompletedTask;
    }

    public string? Load(string clientId)
    {
        var path = GetTokenPath(clientId);
        if (!File.Exists(path))
        {
            return null;
        }

        if (OperatingSystem.IsWindows())
        {
            var encrypted = File.ReadAllBytes(path);
            var plaintext = UnprotectWindows(encrypted);
            try
            {
                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        var raw = File.ReadAllBytes(path);
        try
        {
            return Encoding.UTF8.GetString(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    public void Save(string clientId, string refreshToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(refreshToken);

        var path = GetTokenPath(clientId);

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(_directory);
            var plaintext = Encoding.UTF8.GetBytes(refreshToken);
            byte[] encrypted;
            try
            {
                encrypted = ProtectWindows(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            File.WriteAllBytes(path, encrypted);
            return;
        }

        if (!Directory.Exists(_directory))
        {
            Directory.CreateDirectory(
                _directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        var payload = Encoding.UTF8.GetBytes(refreshToken);
        var tempPath = Path.Combine(_directory, $".refresh-token-tmp-{Guid.NewGuid():N}");
        try
        {
            using (var fs = new FileStream(tempPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                fs.Write(payload);
            }

            File.Move(tempPath, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (File.Exists(tempPath))
            {
                try
                {
                    File.Delete(tempPath);
                }
                catch
                {
                    // Best-effort temp cleanup.
                }
            }
        }
    }

    public void Delete(string clientId)
    {
        var path = GetTokenPath(clientId);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ProtectWindows(byte[] data) =>
        ProtectedData.Protect(data, optionalEntropy: null, DataProtectionScope.CurrentUser);

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectWindows(byte[] data) =>
        ProtectedData.Unprotect(data, optionalEntropy: null, DataProtectionScope.CurrentUser);

    private static string GetDefaultConfigDirectory()
    {
        var configDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrWhiteSpace(configDir))
        {
            configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
                        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        }
        return Path.Combine(configDir, "iap-auther");
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            sb.Append(Array.IndexOf(invalid, ch) >= 0 ? '_' : ch);
        }
        return sb.ToString();
    }
}
