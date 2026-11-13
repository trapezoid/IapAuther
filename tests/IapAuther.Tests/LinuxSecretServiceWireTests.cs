using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using IapAuther.Auth;
using Tmds.DBus.Protocol;

namespace IapAuther.Tests;

public sealed class LinuxSecretServiceWireTests : IAsyncLifetime
{
    private const string ServiceBusName = "org.freedesktop.secrets";
    private const string ServicePath = "/org/freedesktop/secrets";
    private const string DefaultCollectionPath = "/org/freedesktop/secrets/collection/login";

    private readonly string _tempDir;
    private Process? _dbusDaemon;
    private DBusConnection? _serverConnection;
    private MockSecretServiceHandler? _handler;
    private string? _busAddress;

    public LinuxSecretServiceWireTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"iap-auther-dbus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public async Task InitializeAsync()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists("/usr/bin/dbus-daemon"))
        {
            return;
        }

        var socketPath = Path.Combine(_tempDir, "bus.sock");
        _busAddress = $"unix:path={socketPath}";

        var psi = new ProcessStartInfo("/usr/bin/dbus-daemon")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--session");
        psi.ArgumentList.Add("--nofork");
        psi.ArgumentList.Add("--nopidfile");
        psi.ArgumentList.Add($"--address={_busAddress}");
        psi.ArgumentList.Add("--print-address=1");

        _dbusDaemon = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start dbus-daemon.");

        var announced = await _dbusDaemon.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
        if (string.IsNullOrWhiteSpace(announced))
        {
            var stderr = await _dbusDaemon.StandardError.ReadToEndAsync();
            throw new InvalidOperationException($"dbus-daemon exited unexpectedly: {stderr}");
        }
        _busAddress = announced.Trim();

        _handler = new MockSecretServiceHandler();
        _serverConnection = new DBusConnection(_busAddress);
        await _serverConnection.ConnectAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        _serverConnection.AddMethodHandler(_handler);
        var acquired = await _serverConnection.TryRequestNameAsync(ServiceBusName, RequestNameOptions.Default)
            .WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(acquired, "Mock service could not acquire org.freedesktop.secrets on test dbus-daemon.");
    }

    public async Task DisposeAsync()
    {
        _serverConnection?.Dispose();
        if (_dbusDaemon is not null)
        {
            try
            {
                if (!_dbusDaemon.HasExited)
                {
                    _dbusDaemon.Kill(entireProcessTree: true);
                    await _dbusDaemon.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
                }
            }
            catch
            {
                // Best-effort cleanup.
            }
            finally
            {
                _dbusDaemon.Dispose();
            }
        }

        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task SecretService_RoundTripOverwriteIsolateDelete_OverRealDBusDaemon()
    {
        if (!OperatingSystem.IsLinux() || _handler is null || _busAddress is null)
        {
            return;
        }

        IRefreshTokenStore store = new LinuxSecretServiceStore(serviceName: "iap-auther-wire-test", dbusAddress: _busAddress);

        Assert.Null(await store.LoadAsync("client-a"));

        await store.SaveAsync("client-a", "rt-initial");
        await store.SaveAsync("client-b", "rt-other-account");
        Assert.Equal("rt-initial", await store.LoadAsync("client-a"));
        Assert.Equal("rt-other-account", await store.LoadAsync("client-b"));

        // Overwrite replaces existing entry cleanly, including UTF-8 content.
        await store.SaveAsync("client-a", "rt-updated-日本語");
        Assert.Equal("rt-updated-日本語", await store.LoadAsync("client-a"));
        Assert.Equal(2, _handler.ItemCount);

        await store.DeleteAsync("client-a");
        Assert.Null(await store.LoadAsync("client-a"));
        Assert.Equal("rt-other-account", await store.LoadAsync("client-b"));

        // Deleting a non-existent entry is a no-op.
        await store.DeleteAsync("client-a");
        Assert.Equal(1, _handler.ItemCount);
        Assert.True(_handler.ClosedSessionCount >= 6);
    }

    [Fact]
    public async Task SecretService_WhenCollectionLocked_ThrowsCredentialStoreUnavailable()
    {
        if (!OperatingSystem.IsLinux() || _handler is null || _busAddress is null)
        {
            return;
        }

        _handler.IsLocked = true;
        IRefreshTokenStore store = new LinuxSecretServiceStore(serviceName: "iap-auther-wire-test", dbusAddress: _busAddress);

        await Assert.ThrowsAsync<CredentialStoreUnavailableException>(() => store.LoadAsync("client-a").AsTask());
        await Assert.ThrowsAsync<CredentialStoreUnavailableException>(() => store.SaveAsync("client-a", "rt").AsTask());
        await Assert.ThrowsAsync<CredentialStoreUnavailableException>(() => store.DeleteAsync("client-a").AsTask());
    }

    [Fact]
    public async Task SecretService_WhenNoDefaultCollection_ThrowsCredentialStoreUnavailable()
    {
        if (!OperatingSystem.IsLinux() || _handler is null || _busAddress is null)
        {
            return;
        }

        _handler.DefaultCollectionExists = false;
        IRefreshTokenStore store = new LinuxSecretServiceStore(serviceName: "iap-auther-wire-test", dbusAddress: _busAddress);

        await Assert.ThrowsAsync<CredentialStoreUnavailableException>(() => store.LoadAsync("client-a").AsTask());
    }

    [Fact]
    public async Task SecretService_WhenServiceNameMissingOnBus_ThrowsCredentialStoreUnavailable()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists("/usr/bin/dbus-daemon"))
        {
            return;
        }

        // Start a separate empty dbus-daemon with no org.freedesktop.secrets owner.
        var emptyDir = Path.Combine(_tempDir, "empty-bus");
        Directory.CreateDirectory(emptyDir);
        var psi = new ProcessStartInfo("/usr/bin/dbus-daemon")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("--session");
        psi.ArgumentList.Add("--nofork");
        psi.ArgumentList.Add("--nopidfile");
        psi.ArgumentList.Add($"--address=unix:path={Path.Combine(emptyDir, "bus.sock")}");
        psi.ArgumentList.Add("--print-address=1");

        using var daemon = Process.Start(psi)!;
        try
        {
            var address = (await daemon.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)))!.Trim();
            IRefreshTokenStore store = new LinuxSecretServiceStore(dbusAddress: address, timeout: TimeSpan.FromSeconds(2));

            await Assert.ThrowsAsync<CredentialStoreUnavailableException>(() => store.LoadAsync("client-a").AsTask());
        }
        finally
        {
            if (!daemon.HasExited)
            {
                daemon.Kill(entireProcessTree: true);
                await daemon.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));
            }
        }
    }

    [Fact]
    public async Task SecretService_WhenSessionAddressInvalid_ThrowsCredentialStoreUnavailable()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var bogusAddress = $"unix:path={Path.Combine(_tempDir, "nonexistent.sock")}";
        IRefreshTokenStore store = new LinuxSecretServiceStore(dbusAddress: bogusAddress, timeout: TimeSpan.FromSeconds(2));

        await Assert.ThrowsAsync<CredentialStoreUnavailableException>(() => store.LoadAsync("client-a").AsTask());
    }

    private sealed class MockSecretServiceHandler : IPathMethodHandler
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, StoredItem> _items = new(StringComparer.Ordinal);
        private int _nextId;
        private int _nextSessionId;

        private sealed record StoredItem(
            string Path,
            string Label,
            Dictionary<string, string> Attributes,
            byte[] Secret,
            string ContentType);

        public bool IsLocked { get; set; }
        public bool DefaultCollectionExists { get; set; } = true;
        public int ClosedSessionCount { get; private set; }

        public int ItemCount
        {
            get
            {
                lock (_gate)
                {
                    return _items.Count;
                }
            }
        }

        public string Path => ServicePath;

        public bool HandlesChildPaths => true;

        public ValueTask HandleMethodAsync(MethodContext context)
        {
            var req = context.Request;
            var path = req.PathAsString ?? string.Empty;
            var iface = req.InterfaceAsString ?? string.Empty;
            var member = req.MemberAsString ?? string.Empty;

            if (path == ServicePath && iface == "org.freedesktop.Secret.Service")
            {
                switch (member)
                {
                    case "OpenSession":
                        HandleOpenSession(context);
                        return ValueTask.CompletedTask;
                    case "ReadAlias":
                        HandleReadAlias(context);
                        return ValueTask.CompletedTask;
                }
            }
            else if (path == DefaultCollectionPath && iface == "org.freedesktop.DBus.Properties" && member == "Get")
            {
                HandleCollectionPropertyGet(context);
                return ValueTask.CompletedTask;
            }
            else if (path == DefaultCollectionPath && iface == "org.freedesktop.Secret.Collection")
            {
                switch (member)
                {
                    case "SearchItems":
                        HandleSearchItems(context);
                        return ValueTask.CompletedTask;
                    case "CreateItem":
                        HandleCreateItem(context);
                        return ValueTask.CompletedTask;
                }
            }
            else if (path.StartsWith($"{DefaultCollectionPath}/item_", StringComparison.Ordinal) &&
                     iface == "org.freedesktop.Secret.Item")
            {
                switch (member)
                {
                    case "GetSecret":
                        HandleGetSecret(context, path);
                        return ValueTask.CompletedTask;
                    case "Delete":
                        HandleDeleteItem(context, path);
                        return ValueTask.CompletedTask;
                }
            }
            else if (path.StartsWith($"{ServicePath}/session/", StringComparison.Ordinal) &&
                     iface == "org.freedesktop.Secret.Session" &&
                     member == "Close")
            {
                lock (_gate)
                {
                    ClosedSessionCount++;
                }
                if (!context.NoReplyExpected)
                {
                    using var writer = context.CreateReplyWriter(null!);
                    context.Reply(writer.CreateMessage());
                }
                return ValueTask.CompletedTask;
            }

            context.ReplyUnknownMethodError();
            return ValueTask.CompletedTask;
        }

        private void HandleOpenSession(MethodContext context)
        {
            var reader = context.Request.GetBodyReader();
            var algorithm = reader.ReadString();
            _ = reader.ReadVariantValue();
            if (algorithm != "plain")
            {
                context.ReplyError("org.freedesktop.Secret.Error.NotSupported", "Only plain algorithm supported");
                return;
            }

            string sessionPath;
            lock (_gate)
            {
                sessionPath = $"{ServicePath}/session/s{++_nextSessionId}";
            }

            using var writer = context.CreateReplyWriter("vo");
            writer.WriteVariantString(string.Empty);
            writer.WriteObjectPath(sessionPath);
            context.Reply(writer.CreateMessage());
        }

        private void HandleReadAlias(MethodContext context)
        {
            var reader = context.Request.GetBodyReader();
            var alias = reader.ReadString();
            var collection = (alias == "default" && DefaultCollectionExists) ? DefaultCollectionPath : "/";

            using var writer = context.CreateReplyWriter("o");
            writer.WriteObjectPath(collection);
            context.Reply(writer.CreateMessage());
        }

        private void HandleCollectionPropertyGet(MethodContext context)
        {
            var reader = context.Request.GetBodyReader();
            var iface = reader.ReadString();
            var prop = reader.ReadString();
            if (iface == "org.freedesktop.Secret.Collection" && prop == "Locked")
            {
                using var writer = context.CreateReplyWriter("v");
                writer.WriteVariantBool(IsLocked);
                context.Reply(writer.CreateMessage());
                return;
            }

            context.ReplyError("org.freedesktop.DBus.Error.UnknownProperty", $"Unknown property {iface}.{prop}");
        }

        private void HandleSearchItems(MethodContext context)
        {
            var reader = context.Request.GetBodyReader();
            var query = ReadStringDictionary(ref reader);

            ObjectPath[] matches;
            lock (_gate)
            {
                matches = _items.Values
                    .Where(item => query.All(kv =>
                        item.Attributes.TryGetValue(kv.Key, out var val) &&
                        string.Equals(val, kv.Value, StringComparison.Ordinal)))
                    .Select(item => new ObjectPath(item.Path))
                    .ToArray();
            }

            using var writer = context.CreateReplyWriter("ao");
            writer.WriteArray(matches);
            context.Reply(writer.CreateMessage());
        }

        private void HandleCreateItem(MethodContext context)
        {
            var reader = context.Request.GetBodyReader();
            var props = reader.ReadDictionaryOfStringToVariantValue();

            var label = props.TryGetValue("org.freedesktop.Secret.Item.Label", out var labelVar)
                ? labelVar.GetString()
                : string.Empty;
            var attrsDict = props["org.freedesktop.Secret.Item.Attributes"].GetDictionary<string, string>();
            var attrs = new Dictionary<string, string>(attrsDict, StringComparer.Ordinal);

            reader.AlignStruct();
            var sessionPath = reader.ReadObjectPathAsString();
            _ = reader.ReadArrayOfByte(); // parameters
            var secretBytes = reader.ReadArrayOfByte();
            var contentType = reader.ReadString();
            var replace = reader.ReadBool();

            if (string.IsNullOrEmpty(sessionPath) || sessionPath == "/")
            {
                context.ReplyError("org.freedesktop.Secret.Error.NoSession", "Invalid session");
                return;
            }

            string itemPath;
            lock (_gate)
            {
                if (replace)
                {
                    var existing = _items.Values.FirstOrDefault(item => AttributesEqual(item.Attributes, attrs));
                    if (existing is not null)
                    {
                        CryptographicOperations.ZeroMemory(existing.Secret);
                        _items.Remove(existing.Path);
                    }
                }

                itemPath = $"{DefaultCollectionPath}/item_{++_nextId}";
                _items[itemPath] = new StoredItem(itemPath, label, attrs, secretBytes, contentType);
            }

            using var writer = context.CreateReplyWriter("oo");
            writer.WriteObjectPath(itemPath);
            writer.WriteObjectPath("/");
            context.Reply(writer.CreateMessage());
        }

        private void HandleGetSecret(MethodContext context, string path)
        {
            var reader = context.Request.GetBodyReader();
            var session = reader.ReadObjectPathAsString();

            StoredItem? item;
            lock (_gate)
            {
                _items.TryGetValue(path, out item);
            }

            if (item is null)
            {
                context.ReplyError("org.freedesktop.Secret.Error.NoSuchObject", "Item not found");
                return;
            }

            using var writer = context.CreateReplyWriter("(oayays)");
            writer.WriteStructureStart();
            writer.WriteObjectPath(session);
            writer.WriteArray(Array.Empty<byte>());
            writer.WriteArray(item.Secret);
            writer.WriteString(item.ContentType);
            context.Reply(writer.CreateMessage());
        }

        private void HandleDeleteItem(MethodContext context, string path)
        {
            lock (_gate)
            {
                if (_items.Remove(path, out var removed))
                {
                    CryptographicOperations.ZeroMemory(removed.Secret);
                }
            }

            using var writer = context.CreateReplyWriter("o");
            writer.WriteObjectPath("/");
            context.Reply(writer.CreateMessage());
        }

        private static Dictionary<string, string> ReadStringDictionary(ref Reader reader)
        {
            var dict = new Dictionary<string, string>(StringComparer.Ordinal);
            var end = reader.ReadDictionaryStart();
            while (reader.HasNext(end))
            {
                var key = reader.ReadString();
                var value = reader.ReadString();
                dict[key] = value;
            }
            return dict;
        }

        private static bool AttributesEqual(Dictionary<string, string> a, Dictionary<string, string> b)
        {
            if (a.Count != b.Count)
            {
                return false;
            }
            foreach (var (k, v) in a)
            {
                if (!b.TryGetValue(k, out var bv) || !string.Equals(v, bv, StringComparison.Ordinal))
                {
                    return false;
                }
            }
            return true;
        }
    }
}
