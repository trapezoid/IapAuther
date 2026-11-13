using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace IapAuther.Auth;

[SupportedOSPlatform("windows")]
internal sealed class WindowsCredentialStore : IRefreshTokenStore
{
    private const string DefaultTargetPrefix = "iap-auther:oauth-refresh-token";
    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;
    private const int MaxCredentialBlobBytes = 2560; // CRED_MAX_CREDENTIAL_BLOB_SIZE (5 * 512)

    private const int ErrorAccessDenied = 5;
    private const int ErrorNotSupported = 50;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorNotFound = 1168;
    private const int ErrorNoSuchLogonSession = 1312;
    private const int RpcServerUnavailable = 1722;
    private const int EptNotRegistered = 1753;

    private readonly string _targetPrefix;

    public WindowsCredentialStore(string? targetPrefix = null)
    {
        _targetPrefix = string.IsNullOrWhiteSpace(targetPrefix) ? DefaultTargetPrefix : targetPrefix;
    }

    public string BackendName => "windows-credential-manager";

    public ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        var targetName = FormatTargetName(clientId);
        if (!CredReadW(targetName, CredTypeGeneric, 0, out var credPtr))
        {
            var err = Marshal.GetLastPInvokeError();
            if (err == ErrorNotFound)
            {
                return new ValueTask<string?>((string?)null);
            }
            throw MapWin32Error(err, "CredReadW");
        }

        try
        {
            var cred = Marshal.PtrToStructure<NativeCredential>(credPtr);
            if (cred.CredentialBlob == nint.Zero || cred.CredentialBlobSize == 0)
            {
                return new ValueTask<string?>(string.Empty);
            }

            var bytes = new byte[checked((int)cred.CredentialBlobSize)];
            try
            {
                Marshal.Copy(cred.CredentialBlob, bytes, 0, bytes.Length);
                return new ValueTask<string?>(Encoding.UTF8.GetString(bytes));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        finally
        {
            CredFree(credPtr);
        }
    }

    public ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(refreshToken);

        var secretBytes = Encoding.UTF8.GetBytes(refreshToken);
        if (secretBytes.Length > MaxCredentialBlobBytes)
        {
            CryptographicOperations.ZeroMemory(secretBytes);
            throw new InvalidOperationException(
                $"Refresh token ({secretBytes.Length} bytes) exceeds Windows Credential Manager limit ({MaxCredentialBlobBytes} bytes).");
        }

        var targetName = FormatTargetName(clientId);
        nint targetNamePtr = nint.Zero;
        nint commentPtr = nint.Zero;
        nint userNamePtr = nint.Zero;
        nint blobPtr = nint.Zero;

        try
        {
            targetNamePtr = Marshal.StringToHGlobalUni(targetName);
            commentPtr = Marshal.StringToHGlobalUni("IapAuther OAuth2 refresh token");
            userNamePtr = Marshal.StringToHGlobalUni(clientId);

            if (secretBytes.Length > 0)
            {
                blobPtr = Marshal.AllocHGlobal(secretBytes.Length);
                Marshal.Copy(secretBytes, 0, blobPtr, secretBytes.Length);
            }

            var cred = new NativeCredential
            {
                Flags = 0,
                Type = CredTypeGeneric,
                TargetName = targetNamePtr,
                Comment = commentPtr,
                LastWritten = default,
                CredentialBlobSize = (uint)secretBytes.Length,
                CredentialBlob = blobPtr,
                Persist = CredPersistLocalMachine,
                AttributeCount = 0,
                Attributes = nint.Zero,
                TargetAlias = nint.Zero,
                UserName = userNamePtr,
            };

            if (!CredWriteW(ref cred, 0))
            {
                throw MapWin32Error(Marshal.GetLastPInvokeError(), "CredWriteW");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
            if (blobPtr != nint.Zero)
            {
                for (var i = 0; i < secretBytes.Length; i++)
                {
                    Marshal.WriteByte(blobPtr, i, 0);
                }
                Marshal.FreeHGlobal(blobPtr);
            }
            if (targetNamePtr != nint.Zero)
            {
                Marshal.FreeHGlobal(targetNamePtr);
            }
            if (commentPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(commentPtr);
            }
            if (userNamePtr != nint.Zero)
            {
                Marshal.FreeHGlobal(userNamePtr);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        var targetName = FormatTargetName(clientId);
        if (!CredDeleteW(targetName, CredTypeGeneric, 0))
        {
            var err = Marshal.GetLastPInvokeError();
            if (err == ErrorNotFound)
            {
                return ValueTask.CompletedTask;
            }
            throw MapWin32Error(err, "CredDeleteW");
        }

        return ValueTask.CompletedTask;
    }

    private string FormatTargetName(string clientId) => $"{_targetPrefix}:{clientId}";

    private static Exception MapWin32Error(int errorCode, string operation)
    {
        var message = new Win32Exception(errorCode).Message;
        var detail = $"{operation} failed with Win32 error {errorCode}: {message}";

        return errorCode switch
        {
            ErrorNoSuchLogonSession or ErrorServiceNotActive or RpcServerUnavailable or EptNotRegistered or ErrorNotSupported or ErrorAccessDenied
                => new CredentialStoreUnavailableException(detail),
            _ => new InvalidOperationException(detail),
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCredential
    {
        public uint Flags;
        public uint Type;
        public nint TargetName;
        public nint Comment;
        public FILETIME LastWritten;
        public uint CredentialBlobSize;
        public nint CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public nint Attributes;
        public nint TargetAlias;
        public nint UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredReadW(string targetName, uint type, uint flags, out nint credential);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWriteW(ref NativeCredential credential, uint flags);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDeleteW(string targetName, uint type, uint flags);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern void CredFree(nint buffer);
}
