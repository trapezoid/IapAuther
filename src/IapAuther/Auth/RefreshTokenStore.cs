using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace IapAuther.Auth;

internal sealed class RefreshTokenStore
{
    private readonly string _directory;

    public RefreshTokenStore(string? baseDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(baseDirectory))
        {
            _directory = baseDirectory;
        }
        else
        {
            var configDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrWhiteSpace(configDir))
            {
                configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
                            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
            }
            _directory = Path.Combine(configDir, "iap-auther");
        }
    }

    public string GetTokenPath(string clientId)
    {
        var safeId = SanitizeFileName(clientId);
        var suffix = OperatingSystem.IsWindows() ? ".dpapi" : "";
        return Path.Combine(_directory, $"refresh-token-{safeId}{suffix}");
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
            return Encoding.UTF8.GetString(plaintext);
        }

        return File.ReadAllText(path, Encoding.UTF8);
    }

    public void Save(string clientId, string refreshToken)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(_directory);
            var bytes = ProtectWindows(Encoding.UTF8.GetBytes(refreshToken));
            File.WriteAllBytes(GetTokenPath(clientId), bytes);
            return;
        }

        if (!Directory.Exists(_directory))
        {
            Directory.CreateDirectory(
                _directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        var path = GetTokenPath(clientId);
        using var fs = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        var payload = Encoding.UTF8.GetBytes(refreshToken);
        fs.Write(payload);
    }

    [SupportedOSPlatform("windows")]
    private static byte[] ProtectWindows(byte[] data) =>
        ProtectedData.Protect(data, optionalEntropy: null, DataProtectionScope.CurrentUser);

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectWindows(byte[] data) =>
        ProtectedData.Unprotect(data, optionalEntropy: null, DataProtectionScope.CurrentUser);

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
