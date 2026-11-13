using System.CommandLine;
using System.Runtime.InteropServices;
using IapAuther.Cli;

namespace IapAuther;

internal static class ExitCodes
{
    public const int Ok = 0;
    public const int ConfigOrFatalError = 1;
    public const int AuthError = 2;
}

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
        {
            ctx.Cancel = true;
            cts.Cancel();
        });

        return await RunAsync(args, cancellationToken: cts.Token).ConfigureAwait(false);
    }

    internal static async Task<int> RunAsync(
        string[] args,
        TextWriter? output = null,
        TextWriter? error = null,
        CancellationToken cancellationToken = default)
    {
        var root = new RootCommand("Authenticate with Google Cloud Identity-Aware Proxy (IAP) — issue tokens, emit headersHelper JSON, or run as a stdio-to-HTTP MCP proxy.");
        root.Add(TokenCommand.Create(output, error));
        root.Add(HeadersCommand.Create(output, error));
        root.Add(McpProxyCommand.Create(output, error));

        var parseResult = root.Parse(args);
        var invocationConfig = (output is not null || error is not null)
            ? new InvocationConfiguration
            {
                Output = output ?? Console.Out,
                Error = error ?? Console.Error,
            }
            : null;

        return await parseResult.InvokeAsync(invocationConfig, cancellationToken).ConfigureAwait(false);
    }
}
