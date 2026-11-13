using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace IapAuther.Auth;

[SupportedOSPlatform("macos")]
internal sealed class MacOSKeychainStore : IRefreshTokenStore
{
    private const string SecurityFramework = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundationFramework = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const string DefaultServiceName = "iap-auther";

    private const int ErrSecSuccess = 0;
    private const int ErrSecUserCanceled = -128;
    private const int ErrSecNotAvailable = -25291;
    private const int ErrSecAuthFailed = -25293;
    private const int ErrSecNoSuchKeychain = -25294;
    private const int ErrSecDuplicateItem = -25299;
    private const int ErrSecItemNotFound = -25300;
    private const int ErrSecNoDefaultKeychain = -25307;
    private const int ErrSecInteractionNotAllowed = -25308;
    private const int ErrSecInteractionRequired = -25315;
    private const int ErrSecDataNotAvailable = -25316;

    private const uint CfStringEncodingUtf8 = 0x08000100;

    // SecKeychainSetUserInteractionAllowed mutates process-wide state, so serialize operations.
    private static readonly Lock KeychainLock = new();

    private readonly string _serviceName;
    private readonly string? _keychainPath;

    public MacOSKeychainStore(string? serviceName = null, string? keychainPath = null)
    {
        _serviceName = string.IsNullOrWhiteSpace(serviceName) ? DefaultServiceName : serviceName;
        _keychainPath = string.IsNullOrWhiteSpace(keychainPath) ? null : keychainPath;
    }

    public string BackendName => "macos-keychain";

    public ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        var serviceBytes = Encoding.UTF8.GetBytes(_serviceName);
        var accountBytes = Encoding.UTF8.GetBytes(clientId);

        var result = ExecuteNonInteractive(keychainRef =>
        {
            var status = SecKeychainFindGenericPassword(
                keychainRef,
                (uint)serviceBytes.Length,
                serviceBytes,
                (uint)accountBytes.Length,
                accountBytes,
                out var passwordLength,
                out var passwordData,
                nint.Zero);

            if (status == ErrSecItemNotFound)
            {
                return null;
            }
            if (status != ErrSecSuccess)
            {
                throw MapSecError(status, "SecKeychainFindGenericPassword");
            }

            try
            {
                if (passwordData == nint.Zero || passwordLength == 0)
                {
                    return string.Empty;
                }

                var bytes = new byte[checked((int)passwordLength)];
                try
                {
                    Marshal.Copy(passwordData, bytes, 0, bytes.Length);
                    return Encoding.UTF8.GetString(bytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
            finally
            {
                if (passwordData != nint.Zero)
                {
                    SecKeychainItemFreeContent(nint.Zero, passwordData);
                }
            }
        });

        return new ValueTask<string?>(result);
    }

    public ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(refreshToken);

        var serviceBytes = Encoding.UTF8.GetBytes(_serviceName);
        var accountBytes = Encoding.UTF8.GetBytes(clientId);
        var secretBytes = Encoding.UTF8.GetBytes(refreshToken);
        var secretParam = secretBytes.Length == 0 ? new byte[1] : secretBytes;

        try
        {
            ExecuteNonInteractive(keychainRef =>
            {
                var status = SecKeychainAddGenericPassword(
                    keychainRef,
                    (uint)serviceBytes.Length,
                    serviceBytes,
                    (uint)accountBytes.Length,
                    accountBytes,
                    (uint)secretBytes.Length,
                    secretParam,
                    nint.Zero);

                if (status == ErrSecDuplicateItem)
                {
                    status = SecKeychainFindGenericPasswordItemRef(
                        keychainRef,
                        (uint)serviceBytes.Length,
                        serviceBytes,
                        (uint)accountBytes.Length,
                        accountBytes,
                        nint.Zero,
                        nint.Zero,
                        out var itemRef);

                    if (status != ErrSecSuccess)
                    {
                        throw MapSecError(status, "SecKeychainFindGenericPassword(update)");
                    }

                    try
                    {
                        status = SecKeychainItemModifyAttributesAndData(
                            itemRef,
                            nint.Zero,
                            (uint)secretBytes.Length,
                            secretParam);
                    }
                    finally
                    {
                        if (itemRef != nint.Zero)
                        {
                            CFRelease(itemRef);
                        }
                    }
                }

                if (status != ErrSecSuccess)
                {
                    throw MapSecError(status, "SecKeychainAddGenericPassword");
                }

                return 0;
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        var serviceBytes = Encoding.UTF8.GetBytes(_serviceName);
        var accountBytes = Encoding.UTF8.GetBytes(clientId);

        ExecuteNonInteractive(keychainRef =>
        {
            var status = SecKeychainFindGenericPasswordItemRef(
                keychainRef,
                (uint)serviceBytes.Length,
                serviceBytes,
                (uint)accountBytes.Length,
                accountBytes,
                nint.Zero,
                nint.Zero,
                out var itemRef);

            if (status == ErrSecItemNotFound)
            {
                return 0;
            }
            if (status != ErrSecSuccess)
            {
                throw MapSecError(status, "SecKeychainFindGenericPassword(delete)");
            }

            try
            {
                status = SecKeychainItemDelete(itemRef);
                if (status != ErrSecSuccess && status != ErrSecItemNotFound)
                {
                    throw MapSecError(status, "SecKeychainItemDelete");
                }
            }
            finally
            {
                if (itemRef != nint.Zero)
                {
                    CFRelease(itemRef);
                }
            }

            return 0;
        });

        return ValueTask.CompletedTask;
    }

    private T ExecuteNonInteractive<T>(Func<nint, T> action)
    {
        lock (KeychainLock)
        {
            var interactionModified = false;
            byte previousAllowed = 1;
            if (SecKeychainGetUserInteractionAllowed(out previousAllowed) == ErrSecSuccess && previousAllowed != 0)
            {
                if (SecKeychainSetUserInteractionAllowed(0) == ErrSecSuccess)
                {
                    interactionModified = true;
                }
            }

            var keychainRef = nint.Zero;
            try
            {
                if (_keychainPath is not null)
                {
                    var openStatus = SecKeychainOpen(_keychainPath, out keychainRef);
                    if (openStatus != ErrSecSuccess)
                    {
                        throw MapSecError(openStatus, "SecKeychainOpen");
                    }

                    // Validate the target keychain exists cleanly rather than waiting for an opaque error.
                    var statusCheck = SecKeychainGetStatus(keychainRef, out _);
                    if (statusCheck != ErrSecSuccess)
                    {
                        throw MapSecError(statusCheck, "SecKeychainGetStatus");
                    }
                }

                return action(keychainRef);
            }
            finally
            {
                if (keychainRef != nint.Zero)
                {
                    CFRelease(keychainRef);
                }
                if (interactionModified)
                {
                    _ = SecKeychainSetUserInteractionAllowed(previousAllowed);
                }
            }
        }
    }

    private static Exception MapSecError(int status, string operation)
    {
        var description = CopyErrorDescription(status);
        var detail = string.IsNullOrWhiteSpace(description)
            ? $"{operation} failed with OSStatus {status}"
            : $"{operation} failed with OSStatus {status}: {description}";

        return status switch
        {
            ErrSecNotAvailable
                or ErrSecAuthFailed
                or ErrSecNoSuchKeychain
                or ErrSecNoDefaultKeychain
                or ErrSecInteractionNotAllowed
                or ErrSecInteractionRequired
                or ErrSecDataNotAvailable
                or ErrSecUserCanceled
                => new CredentialStoreUnavailableException(detail),
            _ => new InvalidOperationException(detail),
        };
    }

    private static string? CopyErrorDescription(int status)
    {
        var cfStr = SecCopyErrorMessageString(status, nint.Zero);
        if (cfStr == nint.Zero)
        {
            return null;
        }

        try
        {
            var length = CFStringGetLength(cfStr);
            if (length <= 0)
            {
                return null;
            }

            var maxBytes = CFStringGetMaximumSizeForEncoding(length, CfStringEncodingUtf8);
            if (maxBytes <= 0)
            {
                return null;
            }

            var buffer = new byte[checked((int)maxBytes + 1)];
            if (CFStringGetCString(cfStr, buffer, buffer.Length, CfStringEncodingUtf8) == 0)
            {
                return null;
            }

            var nulIndex = Array.IndexOf(buffer, (byte)0);
            var count = nulIndex >= 0 ? nulIndex : buffer.Length;
            return Encoding.UTF8.GetString(buffer, 0, count);
        }
        finally
        {
            CFRelease(cfStr);
        }
    }

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainOpen(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string pathName,
        out nint keychain);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainGetStatus(nint keychain, out uint keychainStatus);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainGetUserInteractionAllowed(out byte state);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainSetUserInteractionAllowed(byte state);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainAddGenericPassword(
        nint keychain,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        uint passwordLength,
        byte[] passwordData,
        nint itemRef);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainFindGenericPassword(
        nint keychainOrArray,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        out uint passwordLength,
        out nint passwordData,
        nint itemRef);

    [DllImport(SecurityFramework, EntryPoint = "SecKeychainFindGenericPassword")]
    private static extern int SecKeychainFindGenericPasswordItemRef(
        nint keychainOrArray,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        nint passwordLengthMustBeZero,
        nint passwordDataMustBeZero,
        out nint itemRef);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainItemModifyAttributesAndData(
        nint itemRef,
        nint attrList,
        uint length,
        byte[] data);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainItemDelete(nint itemRef);

    [DllImport(SecurityFramework)]
    private static extern int SecKeychainItemFreeContent(nint attrList, nint data);

    [DllImport(SecurityFramework)]
    private static extern nint SecCopyErrorMessageString(int status, nint reserved);

    [DllImport(CoreFoundationFramework)]
    private static extern nint CFStringGetLength(nint theString);

    [DllImport(CoreFoundationFramework)]
    private static extern nint CFStringGetMaximumSizeForEncoding(nint length, uint encoding);

    [DllImport(CoreFoundationFramework)]
    private static extern byte CFStringGetCString(nint theString, byte[] buffer, nint bufferSize, uint encoding);

    [DllImport(CoreFoundationFramework)]
    private static extern void CFRelease(nint cf);
}
