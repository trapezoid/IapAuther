using System.CommandLine;
using IapAuther.Auth;
using IapAuther.Logging;
using IapAuther.Mcp;
using ModelContextProtocol.Client;

namespace IapAuther.Cli;

internal static class McpProxyCommand
{
    public static Command Create(TextWriter? output = null, TextWriter? error = null)
    {
        var command = new Command("mcp-proxy", "Bridge a stdio MCP client to an IAP-protected HTTP MCP server using the MCP C# SDK.");

        var authOptions = new SharedAuthOptions();
        authOptions.AddTo(command);

        var downstreamAuthOption = new Option<string?>("--downstream-auth")
        {
            Description = "Value forwarded as the upstream Authorization header; supports env:VAR_NAME indirection.",
            DefaultValueFactory = _ => SharedAuthOptions.EnvOr("IAP_AUTHER_DOWNSTREAM_AUTH", "IAP_MCP_DOWNSTREAM_AUTH"),
        };
        var refreshMarginOption = new Option<string>("--refresh-margin")
        {
            Description = "Refresh the ID token this long before expiry (e.g. 5m, 300s).",
            DefaultValueFactory = _ => SharedAuthOptions.EnvOr("IAP_AUTHER_REFRESH_MARGIN", "IAP_MCP_REFRESH_MARGIN") ?? "5m",
        };
        var timeoutOption = new Option<string>("--timeout")
        {
            Description = "Upstream timeout: total for JSON responses, idle (between reads) for SSE streams (e.g. 120s, 2m).",
            DefaultValueFactory = _ => SharedAuthOptions.EnvOr("IAP_AUTHER_TIMEOUT", "IAP_MCP_TIMEOUT") ?? "120s",
        };
        var transportOption = new Option<string>("--transport")
        {
            Description = "Upstream MCP transport mode: auto, streamable-http, or sse.",
            DefaultValueFactory = _ => SharedAuthOptions.EnvOr("IAP_AUTHER_TRANSPORT", "IAP_MCP_TRANSPORT") ?? "auto",
        };
        var upstreamArg = new Argument<string>("upstream-url")
        {
            Description = "Full URL of the IAP-protected HTTP MCP endpoint.",
        };

        command.Add(downstreamAuthOption);
        command.Add(refreshMarginOption);
        command.Add(timeoutOption);
        command.Add(transportOption);
        command.Add(upstreamArg);

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            var stderr = error ?? Console.Error;

            if (!authOptions.TryCreateLogger(parseResult, error, output, out var logger, out var logError))
            {
                stderr.WriteLine($"iap-auther: {logError}");
                return ExitCodes.ConfigOrFatalError;
            }

            var upstreamRaw = parseResult.GetValue(upstreamArg);
            if (!SharedAuthOptions.TryParseHttpUrl(upstreamRaw, out var upstreamUri) || upstreamUri is null)
            {
                logger!.WriteLine($"iap-auther: invalid upstream URL '{upstreamRaw}' (want e.g. https://my-mcp-xxxx.a.run.app/mcp)");
                return ExitCodes.ConfigOrFatalError;
            }

            var refreshMarginRaw = parseResult.GetValue(refreshMarginOption) ?? "5m";
            if (!DurationParser.TryParse(refreshMarginRaw, out var refreshMargin))
            {
                logger!.WriteLine($"iap-auther: invalid --refresh-margin value '{refreshMarginRaw}'");
                return ExitCodes.ConfigOrFatalError;
            }

            var timeoutRaw = parseResult.GetValue(timeoutOption) ?? "120s";
            if (!DurationParser.TryParse(timeoutRaw, out var timeout))
            {
                logger!.WriteLine($"iap-auther: invalid --timeout value '{timeoutRaw}'");
                return ExitCodes.ConfigOrFatalError;
            }

            var transportRaw = parseResult.GetValue(transportOption) ?? "auto";
            if (!TryParseTransportMode(transportRaw, out var transportMode))
            {
                logger!.WriteLine($"iap-auther: invalid --transport value '{transportRaw}' (want auto, streamable-http, or sse)");
                return ExitCodes.ConfigOrFatalError;
            }

            if (!TryResolveDownstreamAuth(parseResult.GetValue(downstreamAuthOption), out var downstreamAuth, out var dsErr))
            {
                logger!.WriteLine($"iap-auther: {dsErr}");
                return ExitCodes.ConfigOrFatalError;
            }

            if (!authOptions.TryBuildConfig(
                    parseResult,
                    upstreamUri,
                    refreshMargin,
                    out var config,
                    out _,
                    out var errorMessage,
                    existingLogger: logger,
                    errorWriter: error,
                    outWriter: output))
            {
                logger!.WriteLine($"iap-auther: {errorMessage}");
                return ExitCodes.ConfigOrFatalError;
            }

            CachedTokenSource source;
            try
            {
                source = await TokenSourceFactory.CreateAsync(config!, cancellationToken).ConfigureAwait(false);
                // Fail fast: mint one token before touching stdin so auth problems surface immediately.
                await source.GetTokenAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return ExitCodes.ConfigOrFatalError;
            }
            catch (Exception ex)
            {
                logger!.WriteLine($"iap-auther: auth bootstrap failed: {ex.Message}");
                return ExitCodes.AuthError;
            }

            using var authHandler = new IapAuthHandler(source, config!.Audience, downstreamAuth, logger);
            using var activityHandler = new ActivityTrackingHandler(authHandler);
            using var httpClient = new HttpClient(activityHandler)
            {
                // Timeouts are enforced per-request / per-SSE-idle by McpBridge's watchdog.
                Timeout = Timeout.InfiniteTimeSpan,
            };
            using var sdkLoggerFactory = new StderrLoggerFactory(logger!);

            await using var bridge = new McpBridge(
                upstreamUri.ToString(),
                httpClient,
                transportMode: transportMode,
                timeout: timeout,
                logger: logger,
                sdkLoggerFactory: sdkLoggerFactory);

            Exception? runErr = null;
            try
            {
                await bridge.RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Clean cancellation.
            }
            catch (Exception ex)
            {
                runErr = ex;
            }

            using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await bridge.ShutdownAsync(shutdownCts.Token).ConfigureAwait(false);

            if (runErr is not null)
            {
                logger!.Error("Bridge terminated", ("error", runErr.Message));
                return ExitCodes.ConfigOrFatalError;
            }

            return ExitCodes.Ok;
        });

        return command;
    }

    internal static bool TryParseTransportMode(string raw, out HttpTransportMode mode)
    {
        switch (raw.Trim().ToLowerInvariant())
        {
            case "auto":
                mode = HttpTransportMode.AutoDetect;
                return true;
            case "streamable-http":
            case "streamable":
                mode = HttpTransportMode.StreamableHttp;
                return true;
            case "sse":
                mode = HttpTransportMode.Sse;
                return true;
            default:
                mode = HttpTransportMode.AutoDetect;
                return false;
        }
    }

    private static bool TryResolveDownstreamAuth(string? raw, out string? resolved, out string? error)
    {
        resolved = raw;
        error = null;
        if (string.IsNullOrEmpty(raw))
        {
            return true;
        }

        if (raw.StartsWith("env:", StringComparison.Ordinal))
        {
            var envName = raw[4..];
            var envVal = Environment.GetEnvironmentVariable(envName);
            if (string.IsNullOrEmpty(envVal))
            {
                error = $"--downstream-auth points at env:{envName} but {envName} is empty or unset";
                return false;
            }
            resolved = envVal;
        }
        return true;
    }
}
