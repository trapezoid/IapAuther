using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Tmds.DBus.Protocol;

namespace IapAuther.Auth;

[SupportedOSPlatform("linux")]
internal sealed class LinuxSecretServiceStore : IRefreshTokenStore
{
    private const string ServiceBusName = "org.freedesktop.secrets";
    private const string ServiceObjectPath = "/org/freedesktop/secrets";
    private const string ServiceInterface = "org.freedesktop.Secret.Service";
    private const string CollectionInterface = "org.freedesktop.Secret.Collection";
    private const string ItemInterface = "org.freedesktop.Secret.Item";
    private const string SessionInterface = "org.freedesktop.Secret.Session";
    private const string PropertiesInterface = "org.freedesktop.DBus.Properties";

    private const string DefaultServiceName = "iap-auther";
    private const string SchemaName = "org.iapauther.OAuthRefreshToken";

    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    private readonly string _serviceName;
    private readonly string? _dbusAddress;
    private readonly TimeSpan _timeout;

    public LinuxSecretServiceStore(
        string? serviceName = null,
        string? dbusAddress = null,
        TimeSpan? timeout = null)
    {
        _serviceName = string.IsNullOrWhiteSpace(serviceName) ? DefaultServiceName : serviceName;
        _dbusAddress = string.IsNullOrWhiteSpace(dbusAddress) ? null : dbusAddress;
        _timeout = timeout ?? DefaultTimeout;
    }

    public string BackendName => "linux-secret-service";

    public async ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);

        return await ExecuteWithSessionAsync(
            async (connection, sessionPath, collectionPath, ct) =>
            {
                var items = await SearchItemsAsync(connection, collectionPath, clientId, ct).ConfigureAwait(false);
                if (items.Length == 0)
                {
                    return null;
                }

                return await GetItemSecretAsync(connection, items[0].ToString(), sessionPath, ct).ConfigureAwait(false);
            },
            cts.Token,
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(refreshToken);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);

        var secretBytes = Encoding.UTF8.GetBytes(refreshToken);
        try
        {
            await ExecuteWithSessionAsync(
                async (connection, sessionPath, collectionPath, ct) =>
                {
                    await CreateItemAsync(connection, collectionPath, sessionPath, clientId, secretBytes, ct)
                        .ConfigureAwait(false);
                    return 0;
                },
                cts.Token,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    public async ValueTask DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);

        await ExecuteWithSessionAsync(
            async (connection, _, collectionPath, ct) =>
            {
                var items = await SearchItemsAsync(connection, collectionPath, clientId, ct).ConfigureAwait(false);
                foreach (var itemPath in items)
                {
                    await DeleteItemAsync(connection, itemPath.ToString(), ct).ConfigureAwait(false);
                }
                return 0;
            },
            cts.Token,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> ExecuteWithSessionAsync<T>(
        Func<DBusConnection, string, string, CancellationToken, Task<T>> operation,
        CancellationToken linkedCancellationToken,
        CancellationToken userCancellationToken)
    {
        var address = _dbusAddress ?? DBusAddress.Session;
        if (string.IsNullOrWhiteSpace(address))
        {
            throw new CredentialStoreUnavailableException(
                "D-Bus session bus address is not set (DBUS_SESSION_BUS_ADDRESS).");
        }

        using var connection = new DBusConnection(address);
        string? sessionPath = null;
        try
        {
            await connection.ConnectAsync().AsTask().WaitAsync(linkedCancellationToken).ConfigureAwait(false);

            sessionPath = await OpenPlainSessionAsync(connection, linkedCancellationToken).ConfigureAwait(false);
            var collectionPath = await ReadDefaultCollectionAsync(connection, linkedCancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(collectionPath) || collectionPath == "/")
            {
                throw new CredentialStoreUnavailableException(
                    "No default org.freedesktop.secrets collection is available.");
            }

            var isLocked = await IsCollectionLockedAsync(connection, collectionPath, linkedCancellationToken)
                .ConfigureAwait(false);
            if (isLocked)
            {
                throw new CredentialStoreUnavailableException(
                    $"Default Secret Service collection '{collectionPath}' is locked.");
            }

            return await operation(connection, sessionPath, collectionPath, linkedCancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!userCancellationToken.IsCancellationRequested)
        {
            throw new CredentialStoreUnavailableException("Timed out communicating with D-Bus Secret Service.");
        }
        catch (TimeoutException ex)
        {
            throw new CredentialStoreUnavailableException("Timed out communicating with D-Bus Secret Service.", ex);
        }
        catch (DBusConnectFailedException ex)
        {
            throw new CredentialStoreUnavailableException(
                $"Failed to connect to D-Bus session bus: {ex.Message}",
                ex);
        }
        catch (DBusErrorReplyException ex) when (IsUnavailableDBusError(ex.ErrorName))
        {
            throw new CredentialStoreUnavailableException(
                $"Secret Service unavailable ({ex.ErrorName}): {ex.ErrorMessage}",
                ex);
        }
        catch (DBusConnectionException ex)
        {
            throw new CredentialStoreUnavailableException(
                $"D-Bus connection error: {ex.Message}",
                ex);
        }
        finally
        {
            if (!string.IsNullOrEmpty(sessionPath) && sessionPath != "/")
            {
                await TryCloseSessionAsync(connection, sessionPath).ConfigureAwait(false);
            }
        }
    }

    private static Task<string> OpenPlainSessionAsync(
        DBusConnection connection,
        CancellationToken cancellationToken)
    {
        return connection.CallMethodAsync(
            CreateOpenSessionMessage(connection),
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                _ = reader.ReadVariantValue();
                return reader.ReadObjectPathAsString();
            },
            null).WaitAsync(cancellationToken);

        static MessageBuffer CreateOpenSessionMessage(DBusConnection conn)
        {
            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: ServiceObjectPath,
                @interface: ServiceInterface,
                member: "OpenSession",
                signature: "sv",
                flags: MessageFlags.None);
            writer.WriteString("plain");
            writer.WriteVariantString(string.Empty);
            return writer.CreateMessage();
        }
    }

    private static Task<string> ReadDefaultCollectionAsync(
        DBusConnection connection,
        CancellationToken cancellationToken)
    {
        return connection.CallMethodAsync(
            CreateReadAliasMessage(connection),
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                return reader.ReadObjectPathAsString();
            },
            null).WaitAsync(cancellationToken);

        static MessageBuffer CreateReadAliasMessage(DBusConnection conn)
        {
            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: ServiceObjectPath,
                @interface: ServiceInterface,
                member: "ReadAlias",
                signature: "s",
                flags: MessageFlags.None);
            writer.WriteString("default");
            return writer.CreateMessage();
        }
    }

    private static Task<bool> IsCollectionLockedAsync(
        DBusConnection connection,
        string collectionPath,
        CancellationToken cancellationToken)
    {
        return connection.CallMethodAsync(
            CreateGetLockedMessage(connection, collectionPath),
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                return reader.ReadVariantValue().GetBool();
            },
            null).WaitAsync(cancellationToken);

        static MessageBuffer CreateGetLockedMessage(DBusConnection conn, string path)
        {
            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: path,
                @interface: PropertiesInterface,
                member: "Get",
                signature: "ss",
                flags: MessageFlags.None);
            writer.WriteString(CollectionInterface);
            writer.WriteString("Locked");
            return writer.CreateMessage();
        }
    }

    private Task<ObjectPath[]> SearchItemsAsync(
        DBusConnection connection,
        string collectionPath,
        string clientId,
        CancellationToken cancellationToken)
    {
        return connection.CallMethodAsync(
            CreateSearchItemsMessage(connection, collectionPath, _serviceName, clientId),
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                return reader.ReadArrayOfObjectPath();
            },
            null).WaitAsync(cancellationToken);

        static MessageBuffer CreateSearchItemsMessage(
            DBusConnection conn,
            string path,
            string serviceName,
            string accountId)
        {
            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: path,
                @interface: CollectionInterface,
                member: "SearchItems",
                signature: "a{ss}",
                flags: MessageFlags.None);

            var dictStart = writer.WriteDictionaryStart();
            writer.WriteDictionaryEntryStart();
            writer.WriteString("application");
            writer.WriteString(serviceName);
            writer.WriteDictionaryEntryStart();
            writer.WriteString("account");
            writer.WriteString(accountId);
            writer.WriteDictionaryEntryStart();
            writer.WriteString("xdg:schema");
            writer.WriteString(SchemaName);
            writer.WriteDictionaryEnd(dictStart);

            return writer.CreateMessage();
        }
    }

    private static Task<string> GetItemSecretAsync(
        DBusConnection connection,
        string itemPath,
        string sessionPath,
        CancellationToken cancellationToken)
    {
        return connection.CallMethodAsync(
            CreateGetSecretMessage(connection, itemPath, sessionPath),
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                reader.AlignStruct();
                _ = reader.ReadObjectPath();
                _ = reader.ReadArrayOfByte();
                var valueBytes = reader.ReadArrayOfByte();
                _ = reader.ReadString();
                try
                {
                    return Encoding.UTF8.GetString(valueBytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(valueBytes);
                }
            },
            null).WaitAsync(cancellationToken);

        static MessageBuffer CreateGetSecretMessage(DBusConnection conn, string path, string session)
        {
            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: path,
                @interface: ItemInterface,
                member: "GetSecret",
                signature: "o",
                flags: MessageFlags.None);
            writer.WriteObjectPath(session);
            return writer.CreateMessage();
        }
    }

    private async Task CreateItemAsync(
        DBusConnection connection,
        string collectionPath,
        string sessionPath,
        string clientId,
        byte[] secretBytes,
        CancellationToken cancellationToken)
    {
        var (createdItem, promptPath) = await connection.CallMethodAsync(
            CreateCreateItemMessage(connection, collectionPath, sessionPath, _serviceName, clientId, secretBytes),
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                var item = reader.ReadObjectPathAsString();
                var prompt = reader.ReadObjectPathAsString();
                return (item, prompt);
            },
            null).WaitAsync(cancellationToken).ConfigureAwait(false);

        if ((string.IsNullOrEmpty(createdItem) || createdItem == "/") &&
            !string.IsNullOrEmpty(promptPath) && promptPath != "/")
        {
            throw new CredentialStoreUnavailableException(
                "Secret Service requested interactive prompt to store secret.");
        }

        static MessageBuffer CreateCreateItemMessage(
            DBusConnection conn,
            string path,
            string session,
            string serviceName,
            string accountId,
            byte[] secret)
        {
            var attributes = new Dict<string, string>
            {
                ["application"] = serviceName,
                ["account"] = accountId,
                ["xdg:schema"] = SchemaName,
            };
            var properties = new Dictionary<string, VariantValue>(StringComparer.Ordinal)
            {
                [$"{ItemInterface}.Label"] = VariantValue.String($"IapAuther OAuth Refresh Token ({accountId})"),
                [$"{ItemInterface}.Attributes"] = attributes.AsVariantValue(),
            };

            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: path,
                @interface: CollectionInterface,
                member: "CreateItem",
                signature: "a{sv}(oayays)b",
                flags: MessageFlags.None);

            writer.WriteDictionary(properties);
            writer.WriteStructureStart();
            writer.WriteObjectPath(session);
            writer.WriteArray(Array.Empty<byte>());
            writer.WriteArray(secret);
            writer.WriteString("text/plain");
            writer.WriteBool(true);
            return writer.CreateMessage();
        }
    }

    private static async Task DeleteItemAsync(
        DBusConnection connection,
        string itemPath,
        CancellationToken cancellationToken)
    {
        var promptPath = await connection.CallMethodAsync(
            CreateDeleteMessage(connection, itemPath),
            static (Message message, object? _) =>
            {
                var reader = message.GetBodyReader();
                return reader.ReadObjectPathAsString();
            },
            null).WaitAsync(cancellationToken).ConfigureAwait(false);

        if (!string.IsNullOrEmpty(promptPath) && promptPath != "/")
        {
            throw new CredentialStoreUnavailableException(
                "Secret Service requested interactive prompt to delete secret.");
        }

        static MessageBuffer CreateDeleteMessage(DBusConnection conn, string path)
        {
            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: path,
                @interface: ItemInterface,
                member: "Delete",
                signature: null!,
                flags: MessageFlags.None);
            return writer.CreateMessage();
        }
    }

    private static async Task TryCloseSessionAsync(DBusConnection connection, string sessionPath)
    {
        try
        {
            using var closeCts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            await connection.CallMethodAsync(CreateCloseMessage(connection, sessionPath))
                .WaitAsync(closeCts.Token)
                .ConfigureAwait(false);
        }
        catch
        {
            // Best-effort session cleanup.
        }

        static MessageBuffer CreateCloseMessage(DBusConnection conn, string path)
        {
            using var writer = conn.GetMessageWriter();
            writer.WriteMethodCallHeader(
                destination: ServiceBusName,
                path: path,
                @interface: SessionInterface,
                member: "Close",
                signature: null!,
                flags: MessageFlags.NoReplyExpected);
            return writer.CreateMessage();
        }
    }

    private static bool IsUnavailableDBusError(string errorName) => errorName is
        "org.freedesktop.DBus.Error.ServiceUnknown"
        or "org.freedesktop.DBus.Error.NameHasNoOwner"
        or "org.freedesktop.DBus.Error.Spawn.ExecFailed"
        or "org.freedesktop.DBus.Error.Spawn.ChildExited"
        or "org.freedesktop.DBus.Error.Spawn.ChildSignaled"
        or "org.freedesktop.DBus.Error.Spawn.Failed"
        or "org.freedesktop.DBus.Error.NoReply"
        or "org.freedesktop.DBus.Error.TimedOut"
        or "org.freedesktop.DBus.Error.AccessDenied"
        or "org.freedesktop.Secret.Error.IsLocked"
        or "org.freedesktop.Secret.Error.NoSession";
}
