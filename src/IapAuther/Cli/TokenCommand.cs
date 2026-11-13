using System.CommandLine;
using System.Text.Json;
using IapAuther.Auth;

namespace IapAuther.Cli;

internal static class TokenCommand
{
    public static Command Create(TextWriter? output = null, TextWriter? error = null)
    {
        var command = new Command("token", "Mint an IAP authentication token (OIDC ID token or self-signed SA JWT) and print it to stdout.");

        var authOptions = new SharedAuthOptions();
        authOptions.AddTo(command);

        var formatOption = new Option<string>("--format", "-f")
        {
            Description = "Output format: raw (token only), header (Proxy-Authorization: Bearer ...), or json.",
            DefaultValueFactory = _ => "raw",
        };
        command.Add(formatOption);

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

            var format = (parseResult.GetValue(formatOption) ?? "raw").Trim().ToLowerInvariant();
            if (format is not ("raw" or "header" or "json"))
            {
                logger!.WriteLine($"iap-auther: unknown --format '{format}' (want raw, header, or json)");
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

            switch (format)
            {
                case "raw":
                    stdout.WriteLine(token);
                    break;
                case "header":
                    stdout.WriteLine($"Proxy-Authorization: Bearer {token}");
                    break;
                case "json":
                {
                    JwtClaims? claims = null;
                    try
                    {
                        claims = JwtUtils.ExtractClaims(token);
                    }
                    catch (FormatException)
                    {
                    }

                    var payload = JsonSerializer.Serialize(new
                    {
                        token,
                        token_type = "Bearer",
                        header = "Proxy-Authorization",
                        audience = config!.Audience,
                        mode = config.Mode.ToCliString(),
                        expires_at = claims?.ExpiresAt,
                        subject = claims?.Subject,
                        issuer = claims?.Issuer,
                        email = claims?.Email,
                    }, new JsonSerializerOptions { WriteIndented = true });
                    stdout.WriteLine(payload);
                    break;
                }
            }

            return ExitCodes.Ok;
        });

        return command;
    }
}
