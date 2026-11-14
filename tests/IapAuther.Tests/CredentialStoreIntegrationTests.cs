using IapAuther.Auth;

namespace IapAuther.Tests;

public sealed class CredentialStoreIntegrationTests : IDisposable
{
    private readonly string _tempDir;

    public CredentialStoreIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"iap-auther-os-int-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    private static bool RequireOsStoreTests =>
        string.Equals(Environment.GetEnvironmentVariable("IAP_AUTHER_REQUIRE_OS_STORE_TESTS"), "true", StringComparison.OrdinalIgnoreCase);

    [Fact]
    public async Task NativeOsCredentialStore_RoundTripUpdateDeleteAndMigrate_WhenAvailable()
    {
        var runId = Guid.NewGuid().ToString("N");
        var clientA = $"iap-auther-test-client-a-{runId}.apps.googleusercontent.com";
        var clientB = $"iap-auther-test-client-b-{runId}.apps.googleusercontent.com";

        var platformStore = RefreshTokenStore.CreatePlatformOsStore();
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
        {
            Assert.NotNull(platformStore);
            var expectedBackend = OperatingSystem.IsWindows()
                ? "windows-credential-manager"
                : OperatingSystem.IsMacOS()
                    ? "macos-keychain"
                    : "linux-secret-service";
            Assert.Equal(expectedBackend, platformStore!.BackendName);
            await ExerciseBackendAndCoordinatorAsync(
                platformStore,
                $"iap-auther-ci-default-a-{runId}.apps.googleusercontent.com",
                $"iap-auther-ci-default-b-{runId}.apps.googleusercontent.com",
                requireAvailable: OperatingSystem.IsWindows() || RequireOsStoreTests);
        }

        if (OperatingSystem.IsWindows())
        {
            var backend = new WindowsCredentialStore(targetPrefix: $"iap-auther-test-{runId}");
            var otherBackend = new WindowsCredentialStore(targetPrefix: $"iap-auther-test-other-{runId}");
            await ExerciseBackendAndCoordinatorAsync(backend, clientA, clientB, requireAvailable: true, otherBackend);
            return;
        }

        if (OperatingSystem.IsMacOS())
        {
            var serviceName = $"iap-auther-test-{runId}";
            var defaultBackend = new MacOSKeychainStore(serviceName: serviceName);
            var defaultOther = new MacOSKeychainStore(serviceName: $"{serviceName}-other");
            await ExerciseBackendAndCoordinatorAsync(defaultBackend, clientA, clientB, requireAvailable: RequireOsStoreTests, defaultOther);

            var explicitKeychain = Environment.GetEnvironmentVariable("IAP_AUTHER_TEST_MACOS_KEYCHAIN");
            if (!string.IsNullOrWhiteSpace(explicitKeychain))
            {
                var explicitBackend = new MacOSKeychainStore(serviceName: $"{serviceName}-explicit", keychainPath: explicitKeychain);
                var explicitOther = new MacOSKeychainStore(serviceName: $"{serviceName}-explicit-other", keychainPath: explicitKeychain);
                await ExerciseBackendAndCoordinatorAsync(explicitBackend, clientA, clientB, requireAvailable: true, explicitOther);
            }

            // Verify missing explicit keychain cleanly reports unavailability without prompting.
            IRefreshTokenStore missingKeychain = new MacOSKeychainStore(
                serviceName: serviceName,
                keychainPath: Path.Combine(_tempDir, "nonexistent.keychain-db"));
            await Assert.ThrowsAsync<CredentialStoreUnavailableException>(() => missingKeychain.LoadAsync(clientA).AsTask());
            return;
        }

        if (OperatingSystem.IsLinux())
        {
            var backend = new LinuxSecretServiceStore(serviceName: $"iap-auther-test-{runId}");
            var otherBackend = new LinuxSecretServiceStore(serviceName: $"iap-auther-test-other-{runId}");
            await ExerciseBackendAndCoordinatorAsync(backend, clientA, clientB, requireAvailable: RequireOsStoreTests, otherBackend);
        }
    }

    private async Task ExerciseBackendAndCoordinatorAsync(
        IRefreshTokenStore backend,
        string clientA,
        string clientB,
        bool requireAvailable,
        IRefreshTokenStore? isolatedOtherServiceStore = null)
    {
        const string otherClient = "iap-auther-other-client";
        try
        {
            // Verify initial missing state.
            Assert.Null(await backend.LoadAsync(clientA));

            // Save & load.
            await backend.SaveAsync(clientA, "rt-initial");
            await backend.SaveAsync(clientB, "rt-second-client");
            Assert.Equal("rt-initial", await backend.LoadAsync(clientA));
            Assert.Equal("rt-second-client", await backend.LoadAsync(clientB));

            // Update existing item (including multi-byte UTF-8).
            await backend.SaveAsync(clientA, "rt-rotated-日本語");
            Assert.Equal("rt-rotated-日本語", await backend.LoadAsync(clientA));

            // Delete and verify missing again.
            Assert.True(await backend.DeleteAsync(clientA));
            Assert.False(await backend.DeleteAsync(clientA));
            Assert.Null(await backend.LoadAsync(clientA));
            Assert.Equal("rt-second-client", await backend.LoadAsync(clientB));

            // Exercise RefreshTokenStore Auto migration + cleanup against the real OS backend.
            var fileStore = new FileRefreshTokenStore(_tempDir);
            await fileStore.SaveAsync(clientA, "legacy-file-rt");
            var coordinator = new RefreshTokenStore(TokenStoreMode.Auto, backend, fileStore);
            Assert.Equal("legacy-file-rt", await coordinator.LoadAsync(clientA));
            Assert.False(File.Exists(fileStore.GetTokenPath(clientA)));
            Assert.Equal("legacy-file-rt", await backend.LoadAsync(clientA));

            // Exercise RefreshTokenStore Os mode.
            var strictCoordinator = new RefreshTokenStore(TokenStoreMode.Os, backend, fileStore);
            await strictCoordinator.SaveAsync(clientA, "strict-os-rt");
            Assert.Equal("strict-os-rt", await strictCoordinator.LoadAsync(clientA));
            Assert.True(await strictCoordinator.DeleteAsync(clientA));
            Assert.Null(await strictCoordinator.LoadAsync(clientA));

            // Exercise ClearAsync only on isolated test-scoped stores (never on shared default platform service).
            if (isolatedOtherServiceStore is not null)
            {
                await backend.SaveAsync(clientA, "rt-clear-1");
                await backend.SaveAsync(clientB, "rt-clear-2");
                await fileStore.SaveAsync("legacy-clear-only", "rt-legacy");
                await isolatedOtherServiceStore.SaveAsync(otherClient, "rt-other-service");

                var clearResult = await coordinator.ClearDetailedAsync();
                Assert.Equal(3, clearResult.DeletedCount);
                Assert.Equal(2, clearResult.OsDeletedCount);
                Assert.Equal(1, clearResult.FileDeletedCount);
                Assert.Null(await backend.LoadAsync(clientA));
                Assert.Null(await backend.LoadAsync(clientB));
                Assert.Null(await fileStore.LoadAsync("legacy-clear-only"));
                Assert.Equal("rt-other-service", await isolatedOtherServiceStore.LoadAsync(otherClient));
                Assert.Equal(0, await backend.ClearAsync());
            }
        }
        catch (CredentialStoreUnavailableException) when (!requireAvailable)
        {
            // Local environment does not have an unlocked OS credential store daemon/session.
            // GitHub Actions matrix workflow sets IAP_AUTHER_REQUIRE_OS_STORE_TESTS=true to enforce execution.
        }
        finally
        {
            try
            {
                await backend.DeleteAsync(clientA);
                await backend.DeleteAsync(clientB);
                if (isolatedOtherServiceStore is not null)
                {
                    await isolatedOtherServiceStore.DeleteAsync(otherClient);
                }
            }
            catch
            {
                // Best-effort cleanup of test entries.
            }
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
