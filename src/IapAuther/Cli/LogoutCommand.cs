using System.CommandLine;
using System.Text.Json;
using IapAuther.Auth;
using IapAuther.Logging;

namespace IapAuther.Cli;

internal static class LogoutCommand
{
    public static Command Create(
        TextWriter? output = null,
        TextWriter? error = null,
        Func<TokenStoreMode, StderrLogger, RefreshTokenStore>? storeFactory = null)
    {
        var command = new Command("logout", "Clear cached OAuth refresh tokens from the credential store.");
        command.Aliases.Add("clear-tokens");

        var authOptions = new SharedAuthOptions();

        var allOption = new Option<bool>("--all")
        {
            Description = "Clear all cached OAuth refresh tokens stored by iap-auther.",
        };

        var formatOption = new Option<string>("--format", "-f")
        {
            Description = "Output format: text or json.",
            DefaultValueFactory = _ => "text",
        };

        command.Add(authOptions.OAuthClientId);
        command.Add(allOption);
        command.Add(authOptions.TokenStore);
        command.Add(formatOption);
        command.Add(authOptions.LogLevel);
        command.Add(authOptions.LogOutput);

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            var stdout = output ?? Console.Out;
            var stderr = error ?? Console.Error;

            if (!authOptions.TryCreateLogger(parseResult, error, output, out var logger, out var logError))
            {
                stderr.WriteLine($"iap-auther: {logError}");
                return ExitCodes.ConfigOrFatalError;
            }

            var format = (parseResult.GetValue(formatOption) ?? "text").Trim().ToLowerInvariant();
            if (format is not ("text" or "json"))
            {
                logger!.WriteLine($"iap-auther: unknown --format '{format}' (want text or json)");
                return ExitCodes.ConfigOrFatalError;
            }

            var tokenStoreRaw = parseResult.GetValue(authOptions.TokenStore) ?? "auto";
            if (!TokenStoreModeExtensions.TryParse(tokenStoreRaw, out var tokenStoreMode))
            {
                logger!.WriteLine($"iap-auther: unknown --token-store '{tokenStoreRaw}' (want auto, os, or file)");
                return ExitCodes.ConfigOrFatalError;
            }

            var clearAll = parseResult.GetValue(allOption);
            var clientIdResult = parseResult.GetResult(authOptions.OAuthClientId);
            var explicitClientIdPassed = clientIdResult is not null && !clientIdResult.Implicit;
            var clientId = parseResult.GetValue(authOptions.OAuthClientId);

            if (clearAll && explicitClientIdPassed)
            {
                logger!.WriteLine("iap-auther: cannot combine --oauth-client-id with --all");
                return ExitCodes.ConfigOrFatalError;
            }

            if (!clearAll)
            {
                if (explicitClientIdPassed && string.IsNullOrWhiteSpace(clientId))
                {
                    logger!.WriteLine("iap-auther: --oauth-client-id must not be empty");
                    return ExitCodes.ConfigOrFatalError;
                }

                if (string.IsNullOrWhiteSpace(clientId))
                {
                    logger!.WriteLine(
                        "iap-auther: either --oauth-client-id <id> (or IAP_AUTHER_OAUTH_CLIENT_ID) or --all is required");
                    return ExitCodes.ConfigOrFatalError;
                }
            }

            var store = storeFactory is not null
                ? storeFactory(tokenStoreMode, logger!)
                : new RefreshTokenStore(tokenStoreMode, logger: logger);

            logger!.Info(
                "Clearing cached OAuth refresh tokens",
                ("scope", clearAll ? "all" : "client"),
                ("token_store", tokenStoreMode.ToCliString()));

            TokenClearResult result;
            try
            {
                result = clearAll
                    ? await store.ClearDetailedAsync(cancellationToken).ConfigureAwait(false)
                    : await store.DeleteDetailedAsync(clientId!, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return ExitCodes.ConfigOrFatalError;
            }
            catch (Exception ex)
            {
                logger.WriteLine($"iap-auther: clearing cached tokens failed: {ex.Message}");
                return ExitCodes.AuthError;
            }

            if (format == "json")
            {
                var payload = JsonSerializer.Serialize(new
                {
                    scope = clearAll ? "all" : "client",
                    oauth_client_id = clearAll ? null : clientId,
                    token_store = tokenStoreMode.ToCliString(),
                    deleted_count = result.DeletedCount,
                    os_deleted_count = result.OsDeletedCount,
                    file_deleted_count = result.FileDeletedCount,
                    os_backend = result.OsBackend,
                    file_backend = result.FileBackend,
                    os_unavailable_fallback = result.OsUnavailableFallback,
                }, new JsonSerializerOptions { WriteIndented = true });
                stdout.WriteLine(payload);
            }
            else
            {
                stdout.WriteLine(FormatTextSummary(clearAll, clientId, result));
            }

            return ExitCodes.Ok;
        });

        return command;
    }

    private static string FormatTextSummary(bool clearAll, string? clientId, TokenClearResult result)
    {
        var details = FormatBackendDetails(result);
        if (clearAll)
        {
            return result.DeletedCount == 0
                ? $"No cached OAuth refresh tokens found ({details})."
                : $"Cleared {result.DeletedCount} cached OAuth refresh token(s) ({details}).";
        }

        return result.DeletedCount == 0
            ? $"No cached OAuth refresh token found for '{clientId}' ({details})."
            : $"Cleared cached OAuth refresh token for '{clientId}' ({details}).";
    }

    private static string FormatBackendDetails(TokenClearResult result)
    {
        var parts = new List<string>(2);
        if (result.OsBackend is not null)
        {
            parts.Add(result.OsUnavailableFallback
                ? $"{result.OsBackend}: unavailable"
                : $"{result.OsBackend}: {result.OsDeletedCount}");
        }
        else if (result.OsUnavailableFallback)
        {
            parts.Add("os-store: unavailable");
        }

        if (result.FileBackend is not null)
        {
            parts.Add($"{result.FileBackend}: {result.FileDeletedCount}");
        }

        return string.Join(", ", parts);
    }
}
