using System.CommandLine;
using System.Text.Encodings.Web;
using System.Text.Json;
using IapAuther.Auth;

namespace IapAuther.Cli;

internal static class HeadersCommand
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static Command Create(TextWriter? output = null, TextWriter? error = null)
    {
        var command = new Command(
            "headers",
            "Mint an IAP authentication token and print a headersHelper-compatible JSON object to stdout.");

        var authOptions = new SharedAuthOptions();
        authOptions.AddTo(command);

        var headerOption = new Option<string[]>("--header", "-H")
        {
            Description = "Additional HTTP header in 'Name: Value' format (repeatable; value supports env:VAR_NAME indirection).",
        };
        command.Add(headerOption);

        var upstreamArg = new Argument<string?>("upstream-url")
        {
            Description = "Optional upstream URL used to derive --audience when --audience is omitted.",
            Arity = ArgumentArity.ZeroOrOne,
        };
        command.Add(upstreamArg);

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            var stdout = output ?? Console.Out;
            var stderr = error ?? Console.Error;

            if (!authOptions.TryCreateLogger(parseResult, error, output, out var logger, out var logError))
            {
                stderr.WriteLine($"iap-auther: {logError}");
                return ExitCodes.ConfigOrFatalError;
            }

            if (!TryParseExtraHeaders(parseResult.GetValue(headerOption), out var extraHeaders, out var headerError))
            {
                logger!.WriteLine($"iap-auther: {headerError}");
                return ExitCodes.ConfigOrFatalError;
            }

            var upstreamRaw = parseResult.GetValue(upstreamArg);
            Uri? upstreamUri = null;
            if (!string.IsNullOrWhiteSpace(upstreamRaw) &&
                !SharedAuthOptions.TryParseHttpUrl(upstreamRaw, out upstreamUri))
            {
                logger!.WriteLine($"iap-auther: invalid upstream URL '{upstreamRaw}' (want e.g. https://my-svc-xxxx.a.run.app/mcp)");
                return ExitCodes.ConfigOrFatalError;
            }

            if (!authOptions.TryBuildConfig(
                    parseResult,
                    upstreamUri,
                    TimeSpan.FromMinutes(5),
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

            string token;
            try
            {
                var source = await TokenSourceFactory.CreateAsync(config!, cancellationToken).ConfigureAwait(false);
                token = await source.GetTokenAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return ExitCodes.ConfigOrFatalError;
            }
            catch (Exception ex)
            {
                logger!.WriteLine($"iap-auther: auth failed: {ex.Message}");
                return ExitCodes.AuthError;
            }

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Proxy-Authorization"] = $"Bearer {token}",
            };
            foreach (var (name, value) in extraHeaders)
            {
                headers[name] = value;
            }

            stdout.WriteLine(JsonSerializer.Serialize(headers, JsonOptions));
            return ExitCodes.Ok;
        });

        return command;
    }

    internal static bool TryParseExtraHeaders(
        IEnumerable<string>? rawHeaders,
        out Dictionary<string, string> headers,
        out string? error)
    {
        headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        error = null;

        if (rawHeaders is null)
        {
            return true;
        }

        foreach (var raw in rawHeaders)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                error = "invalid --header value (expected 'Name: Value')";
                return false;
            }

            var colonIndex = raw.IndexOf(':');
            if (colonIndex <= 0)
            {
                error = $"invalid --header '{raw}' (expected 'Name: Value')";
                return false;
            }

            var name = raw[..colonIndex].Trim();
            if (!IsValidHeaderName(name))
            {
                error = $"invalid header name '{name}' in --header";
                return false;
            }

            if (string.Equals(name, "Proxy-Authorization", StringComparison.OrdinalIgnoreCase))
            {
                error = "cannot override 'Proxy-Authorization' via --header (it is generated from the IAP token)";
                return false;
            }

            var rawValue = raw[(colonIndex + 1)..].Trim();
            string resolvedValue;
            if (rawValue.StartsWith("env:", StringComparison.Ordinal))
            {
                var envName = rawValue[4..];
                if (string.IsNullOrWhiteSpace(envName))
                {
                    error = $"--header '{name}' uses empty 'env:' reference";
                    return false;
                }

                var envValue = Environment.GetEnvironmentVariable(envName);
                if (string.IsNullOrEmpty(envValue))
                {
                    error = $"--header '{name}' points at env:{envName} but {envName} is empty or unset";
                    return false;
                }

                resolvedValue = envValue;
            }
            else
            {
                resolvedValue = rawValue;
            }

            if (ContainsInvalidHeaderValueChars(resolvedValue))
            {
                error = $"invalid control characters in value for header '{name}'";
                return false;
            }

            // Replace any existing case-insensitive key so the latest casing and value win.
            headers.Remove(name);
            headers[name] = resolvedValue;
        }

        return true;
    }

    private static bool IsValidHeaderName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        foreach (var ch in name)
        {
            if (ch <= ' ' || ch >= 0x7f || "()<>@,;:\\\"/[]?={}".Contains(ch))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ContainsInvalidHeaderValueChars(string value)
    {
        foreach (var ch in value)
        {
            if (ch == '\r' || ch == '\n' || ch == '\0')
            {
                return true;
            }
        }

        return false;
    }
}
