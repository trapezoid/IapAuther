using System.CommandLine;
using IapAuther.Auth;
using IapAuther.Iap;
using IapAuther.Logging;

namespace IapAuther.Cli;

internal sealed class SharedAuthOptions
{
    public Option<string?> Audience { get; } = new("--audience", "-a")
    {
        Description = "Token audience: IAP OAuth client ID (LB-backed IAP) or service URL. " +
                      "Defaults to the origin of UPSTREAM_URL, or the exact endpoint for signjwt (pass <origin>/* for all paths).",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_AUDIENCE", "IAP_MCP_AUDIENCE"),
    };

    public Option<string> Credentials { get; } = new("--credentials", "-c")
    {
        Description = "Credential source: auto, adc, impersonate, oauth, signjwt.",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_CREDENTIALS", "IAP_MCP_CREDENTIALS") ?? "auto",
    };

    public Option<string?> ImpersonateServiceAccount { get; } = new("--impersonate-service-account", "-s")
    {
        Description = "Target service account email (impersonate mode mints an ID token; signjwt mode signs a self-signed JWT).",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_IMPERSONATE_SA", "IAP_MCP_IMPERSONATE_SA"),
    };

    public Option<string?> CredentialFile { get; } = new("--credential-file")
    {
        Description = "Path to a Google service account JSON key or ADC credential file.",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_CREDENTIAL_FILE"),
    };

    public Option<string?> OAuthClientId { get; } = new("--oauth-client-id")
    {
        Description = "Desktop OAuth client ID (env: IAP_AUTHER_OAUTH_CLIENT_ID / IAP_MCP_OAUTH_CLIENT_ID).",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_OAUTH_CLIENT_ID", "IAP_MCP_OAUTH_CLIENT_ID"),
    };

    public Option<string?> OAuthClientSecret { get; } = new("--oauth-client-secret")
    {
        Description = "Desktop OAuth client secret (env: IAP_AUTHER_OAUTH_CLIENT_SECRET / IAP_MCP_OAUTH_CLIENT_SECRET).",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_OAUTH_CLIENT_SECRET", "IAP_MCP_OAUTH_CLIENT_SECRET"),
    };

    public Option<string> TokenStore { get; } = new("--token-store")
    {
        Description = "OAuth refresh token store: auto (OS credential store with file fallback), os (OS credential store only), or file.",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_TOKEN_STORE", "IAP_MCP_TOKEN_STORE") ?? "auto",
    };

    public Option<bool> NoBrowser { get; } = new("--no-browser")
    {
        Description = "Do not automatically open a browser during OAuth login; print the URL to log output (stderr by default) instead.",
    };

    public Option<string> LogLevel { get; } = new("--log-level", "-l")
    {
        Description = "Log level: debug, info, warn, error.",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_LOG", "IAP_MCP_LOG") ?? "warn",
    };

    public Option<string> LogOutput { get; } = new("--log-output")
    {
        Description = "Log destination: stderr (default), stdout, or both (including stdout alongside stderr; breaks machine-readable stdout in token/mcp-proxy unless debugging).",
        DefaultValueFactory = _ => EnvOr("IAP_AUTHER_LOG_OUTPUT", "IAP_MCP_LOG_OUTPUT") ?? "stderr",
    };

    public void AddTo(Command command)
    {
        command.Add(Audience);
        command.Add(Credentials);
        command.Add(ImpersonateServiceAccount);
        command.Add(CredentialFile);
        command.Add(OAuthClientId);
        command.Add(OAuthClientSecret);
        command.Add(TokenStore);
        command.Add(NoBrowser);
        command.Add(LogLevel);
        command.Add(LogOutput);
    }

    public bool TryCreateLogger(
        ParseResult parseResult,
        TextWriter? errorWriter,
        TextWriter? outWriter,
        out StderrLogger? logger,
        out string? errorMessage)
    {
        logger = null;
        errorMessage = null;

        var logLevelRaw = parseResult.GetValue(LogLevel) ?? "warn";
        if (!StderrLogger.TryParseLevel(logLevelRaw, out var parsedLevel))
        {
            errorMessage = $"unknown --log-level '{logLevelRaw}' (want debug, info, warn, or error)";
            return false;
        }

        var logOutputRaw = parseResult.GetValue(LogOutput) ?? "stderr";
        if (!StderrLogger.TryParseOutputMode(logOutputRaw, out var outputMode))
        {
            errorMessage = $"unknown --log-output '{logOutputRaw}' (want stderr, stdout, or both)";
            return false;
        }

        logger = new StderrLogger(parsedLevel, outputMode, errorWriter, outWriter);
        return true;
    }

    public bool TryBuildConfig(
        ParseResult parseResult,
        Uri? upstreamUri,
        TimeSpan refreshMargin,
        out AuthConfig? config,
        out StderrLogger? logger,
        out string? errorMessage,
        StderrLogger? existingLogger = null,
        TextWriter? errorWriter = null,
        TextWriter? outWriter = null)
    {
        config = null;
        logger = existingLogger;
        errorMessage = null;

        if (logger is null && !TryCreateLogger(parseResult, errorWriter, outWriter, out logger, out errorMessage))
        {
            return false;
        }

        var credRaw = parseResult.GetValue(Credentials) ?? "auto";
        if (!CredentialModeExtensions.TryParse(credRaw, out var mode))
        {
            errorMessage = $"unknown --credentials mode '{credRaw}' (want auto, adc, impersonate, oauth, or signjwt)";
            return false;
        }

        var tokenStoreRaw = parseResult.GetValue(TokenStore) ?? "auto";
        if (!TokenStoreModeExtensions.TryParse(tokenStoreRaw, out var tokenStoreMode))
        {
            errorMessage = $"unknown --token-store '{tokenStoreRaw}' (want auto, os, or file)";
            return false;
        }

        var impersonateSa = parseResult.GetValue(ImpersonateServiceAccount);
        if (!string.IsNullOrWhiteSpace(impersonateSa) && mode == CredentialMode.Auto)
        {
            mode = CredentialMode.Impersonate;
        }

        var audience = parseResult.GetValue(Audience);
        if (string.IsNullOrWhiteSpace(audience))
        {
            if (upstreamUri is null)
            {
                errorMessage = "either --audience or an upstream URL is required";
                return false;
            }
            audience = AudienceResolver.ResolveDefaultAudience(mode, upstreamUri);
            logger!.Info("No --audience given; derived from upstream URL", ("mode", mode.ToCliString()), ("audience", audience));
        }

        config = new AuthConfig
        {
            Mode = mode,
            Audience = audience,
            ImpersonateServiceAccount = impersonateSa,
            CredentialFile = parseResult.GetValue(CredentialFile),
            OAuthClientId = parseResult.GetValue(OAuthClientId),
            OAuthClientSecret = parseResult.GetValue(OAuthClientSecret),
            TokenStore = tokenStoreMode,
            RefreshMargin = refreshMargin,
            NoBrowser = parseResult.GetValue(NoBrowser),
            Logger = logger,
        };
        return true;
    }

    public static string? EnvOr(params string[] names)
    {
        foreach (var name in names)
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrEmpty(value))
            {
                return value;
            }
        }
        return null;
    }

    public static bool TryParseHttpUrl(string? raw, out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var parsed))
        {
            return false;
        }
        if (!string.Equals(parsed.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (string.IsNullOrEmpty(parsed.Host))
        {
            return false;
        }
        uri = parsed;
        return true;
    }
}
