using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using IapAuther.Cli;
using IapAuther.Iap;
using IapAuther.Mcp;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace IapAuther.Tests;

public sealed class McpBridgeTests
{
    private static async Task<(WebApplication App, string BaseUrl)> StartTestServerAsync(RequestDelegate handler)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        var app = builder.Build();
        app.Run(handler);
        await app.StartAsync();

        var addresses = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
        var baseUrl = addresses.Addresses.First();
        return (app, baseUrl);
    }

    private sealed class StubAuthInjectHandler : DelegatingHandler
    {
        public StubAuthInjectHandler() : base(new HttpClientHandler { AllowAutoRedirect = false }) { }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.ProxyAuthorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "stub-token");
            return base.SendAsync(request, cancellationToken);
        }
    }

    private sealed class SyncMemoryStream : Stream
    {
        private readonly Lock _lock = new();
        private readonly MemoryStream _ms = new();

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (_lock)
            {
                _ms.Write(buffer, offset, count);
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                _ms.Write(buffer.Span);
            }
            return ValueTask.CompletedTask;
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public string GetText()
        {
            lock (_lock)
            {
                return Encoding.UTF8.GetString(_ms.GetBuffer(), 0, (int)_ms.Length);
            }
        }
    }

    private static MemoryStream Utf8Stream(string text) => new(Encoding.UTF8.GetBytes(text));

    private static List<JsonElement> ParseOutputLines(string stdout)
    {
        var results = new List<JsonElement>();
        foreach (var raw in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            using var doc = JsonDocument.Parse(raw);
            results.Add(doc.RootElement.Clone());
        }
        return results;
    }

    [Fact]
    public async Task Bridge_RoundTripJsonAndShutdownDelete()
    {
        var deletedSessions = new ConcurrentQueue<string>();

        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (!ctx.Request.Headers.ProxyAuthorization.ToString().StartsWith("Bearer ", StringComparison.Ordinal))
            {
                ctx.Response.Headers[IapClassifier.GeneratedResponseHeader] = "true";
                ctx.Response.Headers.Location = "https://accounts.google.com/o/oauth2/v2/auth";
                ctx.Response.StatusCode = StatusCodes.Status302Found;
                return;
            }

            if (HttpMethods.IsGet(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;
            }

            if (HttpMethods.IsDelete(ctx.Request.Method))
            {
                deletedSessions.Enqueue(ctx.Request.Headers["Mcp-Session-Id"].ToString());
                ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            using var reader = new StreamReader(ctx.Request.Body);
            var body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var method = root.TryGetProperty("method", out var mp) ? mp.GetString() : "";
            if (!root.TryGetProperty("id", out var idProp))
            {
                ctx.Response.StatusCode = StatusCodes.Status202Accepted;
                return;
            }

            string result;
            if (method == "initialize")
            {
                ctx.Response.Headers["Mcp-Session-Id"] = "sess-123";
                result = """{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"echo","version":"1"}}""";
            }
            else
            {
                if (ctx.Request.Headers["Mcp-Session-Id"].ToString() != "sess-123")
                {
                    ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }
                Assert.Equal(method, ctx.Request.Headers["Mcp-Method"].ToString());
                result = JsonSerializer.Serialize(new { echoedMethod = method });
            }

            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync($"{{\"jsonrpc\":\"2.0\",\"id\":{idProp.GetRawText()},\"result\":{result}}}");
        });

        await using var server = app;
        using var client = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}""" + "\n" +
            """{"jsonrpc":"2.0","method":"notifications/initialized"}""" + "\n" +
            """{"jsonrpc":"2.0","id":2,"method":"tools/list"}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/mcp",
            client,
            timeout: TimeSpan.FromSeconds(5),
            reconnectDelay: TimeSpan.FromMilliseconds(5),
            inputStream: input,
            outputStream: output);

        using var cts = new CancellationTokenSource();
        await bridge.RunAsync(cts.Token);
        await bridge.ShutdownAsync(CancellationToken.None);
        cts.Cancel();

        var lines = ParseOutputLines(output.GetText());
        Assert.Equal(2, lines.Count);
        var byId = lines.ToDictionary(m => m.GetProperty("id").GetInt32());
        Assert.True(byId[1].TryGetProperty("result", out _));
        Assert.Equal("tools/list", byId[2].GetProperty("result").GetProperty("echoedMethod").GetString());
        Assert.Equal(["sess-123"], deletedSessions.ToArray());
    }

    [Fact]
    public async Task Bridge_RoundTripSse()
    {
        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (HttpMethods.IsGet(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;
            }

            if (HttpMethods.IsDelete(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            using var reader = new StreamReader(ctx.Request.Body);
            var body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            var method = doc.RootElement.GetProperty("method").GetString();
            var idRaw = doc.RootElement.GetProperty("id").GetRawText();

            if (method == "initialize")
            {
                ctx.Response.Headers["Mcp-Session-Id"] = "sess-sse";
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(
                    $"{{\"jsonrpc\":\"2.0\",\"id\":{idRaw},\"result\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"serverInfo\":{{\"name\":\"test\",\"version\":\"1\"}}}}}}");
                return;
            }

            ctx.Response.ContentType = "text/event-stream";
            await ctx.Response.WriteAsync($"event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{idRaw},\"result\":{{\"echoedMethod\":\"{method}\"}}}}\n\n");
        });

        await using var server = app;
        using var client = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}""" + "\n" +
            """{"jsonrpc":"2.0","id":2,"method":"tools/call"}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/mcp",
            client,
            timeout: TimeSpan.FromSeconds(5),
            reconnectDelay: TimeSpan.FromMilliseconds(5),
            inputStream: input,
            outputStream: output);

        using var cts = new CancellationTokenSource();
        await bridge.RunAsync(cts.Token);
        await bridge.ShutdownAsync(CancellationToken.None);
        cts.Cancel();

        var lines = ParseOutputLines(output.GetText());
        Assert.Equal(2, lines.Count);
        Assert.Contains(lines, m => m.GetProperty("id").GetInt32() == 2 &&
                                    m.GetProperty("result").GetProperty("echoedMethod").GetString() == "tools/call");
    }

    [Fact]
    public async Task Bridge_StandaloneGetStreamAndLastEventIdReconnect()
    {
        var lastIds = new ConcurrentQueue<string>();
        var sessions = new ConcurrentQueue<string>();
        var getCount = 0;
        var reconnected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (HttpMethods.IsPost(ctx.Request.Method))
            {
                ctx.Response.Headers["Mcp-Session-Id"] = "sess-get";
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(
                    """{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}""");
                return;
            }

            if (HttpMethods.IsDelete(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            if (HttpMethods.IsGet(ctx.Request.Method))
            {
                lastIds.Enqueue(ctx.Request.Headers["Last-Event-ID"].ToString());
                sessions.Enqueue(ctx.Request.Headers["Mcp-Session-Id"].ToString());
                var n = Interlocked.Increment(ref getCount);
                if (n == 1)
                {
                    ctx.Response.ContentType = "text/event-stream";
                    await ctx.Response.WriteAsync("id: 5\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n");
                    await ctx.Response.Body.FlushAsync();
                    return;
                }
                if (n == 2)
                {
                    reconnected.TrySetResult();
                }
                ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            }
        });

        await using var server = app;
        using var client = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/mcp",
            client,
            timeout: TimeSpan.FromSeconds(5),
            reconnectDelay: TimeSpan.FromMilliseconds(10),
            inputStream: input,
            outputStream: output);

        using var cts = new CancellationTokenSource();
        await bridge.RunAsync(cts.Token);

        await reconnected.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await bridge.ShutdownAsync(CancellationToken.None);
        cts.Cancel();

        Assert.Contains("notifications/tools/list_changed", output.GetText());
        var ids = lastIds.ToArray();
        Assert.True(ids.Length >= 2);
        Assert.Equal("", ids[0]);
        Assert.Equal("5", ids[1]);
        Assert.All(sessions.ToArray(), s => Assert.Equal("sess-get", s));
    }

    [Fact]
    public async Task Bridge_ResumesDroppedSseResponse()
    {
        var resumeIds = new ConcurrentQueue<string>();
        var firstEventDelivered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (HttpMethods.IsPost(ctx.Request.Method))
            {
                ctx.Response.ContentType = "text/event-stream";
                await ctx.Response.WriteAsync("id: r1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n");
                await ctx.Response.Body.FlushAsync();
                await firstEventDelivered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                ctx.Abort();
                return;
            }

            if (HttpMethods.IsGet(ctx.Request.Method))
            {
                resumeIds.Enqueue(ctx.Request.Headers["Last-Event-ID"].ToString());
                ctx.Response.ContentType = "text/event-stream";
                await ctx.Response.WriteAsync("id: r2\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\n\n");
                return;
            }

            ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        });

        await using var server = app;
        using var client = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream("""{"jsonrpc":"2.0","id":2,"method":"tools/call"}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/mcp",
            client,
            timeout: TimeSpan.FromSeconds(5),
            reconnectDelay: TimeSpan.FromMilliseconds(5),
            inputStream: input,
            outputStream: output);

        var runTask = bridge.RunAsync(CancellationToken.None);

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!output.GetText().Contains("notifications/progress", StringComparison.Ordinal))
        {
            if (DateTime.UtcNow > deadline)
            {
                firstEventDelivered.TrySetResult();
                throw new TimeoutException($"Timed out waiting for r1 event; stdout: {output.GetText()}");
            }
            await Task.Delay(5);
        }
        firstEventDelivered.TrySetResult();

        await runTask;

        var text = output.GetText();
        Assert.Contains("notifications/progress", text);
        Assert.Contains("\"ok\":true", text);
        Assert.DoesNotContain("\"error\"", text);
        Assert.Equal(["r1"], resumeIds.ToArray());
    }

    [Fact]
    public async Task Bridge_TimeoutIsIdleNotTotalForSseAndResetsOnComments()
    {
        var timeout = TimeSpan.FromMilliseconds(350);
        var gap = TimeSpan.FromMilliseconds(120);
        const int keepalives = 4; // 4 * 120ms = 480ms > 350ms total timeout

        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (HttpMethods.IsGet(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;
            }

            ctx.Response.ContentType = "text/event-stream";
            for (var i = 1; i <= keepalives; i++)
            {
                // Alternate SSE comments and JSON-RPC progress notifications to verify ActivityTrackingHandler + MessageReader reset.
                if (i % 2 == 1)
                {
                    await ctx.Response.WriteAsync(": keepalive\n\n");
                }
                else
                {
                    await ctx.Response.WriteAsync($"data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progress\":{i}}}}}\n\n");
                }
                await ctx.Response.Body.FlushAsync();
                await Task.Delay(gap, ctx.RequestAborted);
            }
            await ctx.Response.WriteAsync("data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"done\":true}}\n\n");
            await ctx.Response.Body.FlushAsync();
        });

        await using var server = app;
        using var activityHandler = new ActivityTrackingHandler(new HttpClientHandler());
        using var client = new HttpClient(activityHandler) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream("""{"jsonrpc":"2.0","id":2,"method":"tools/call"}""" + "\n");

        await using var bridge = new McpBridge(baseUrl + "/mcp", client, timeout: timeout, inputStream: input, outputStream: output);
        await bridge.RunAsync(CancellationToken.None);

        var text = output.GetText();
        Assert.Contains("\"done\":true", text);
        Assert.DoesNotContain("\"error\"", text);
        var lines = ParseOutputLines(text);
        Assert.Equal(3, lines.Count); // 2 progress notifications + 1 final result
    }

    [Fact]
    public async Task Bridge_TimeoutFiresOnSilentUpstream()
    {
        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), ctx.RequestAborted);
            }
            catch (OperationCanceledException)
            {
            }
        });

        await using var server = app;
        using var client = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream("""{"jsonrpc":"2.0","id":42,"method":"tools/list"}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/mcp",
            client,
            timeout: TimeSpan.FromMilliseconds(150),
            inputStream: input,
            outputStream: output);

        await bridge.RunAsync(CancellationToken.None);

        var lines = ParseOutputLines(output.GetText());
        Assert.Single(lines);
        Assert.Equal(42, lines[0].GetProperty("id").GetInt32());
        var errMsg = lines[0].GetProperty("error").GetProperty("message").GetString()!;
        Assert.Contains("timed out", errMsg);
    }

    [Fact]
    public async Task Bridge_RecoversFromSessionExpiry404()
    {
        var gate = new Lock();
        var gen = 0;
        var validSession = "";
        var initCount = 0;
        var notifyCount = 0;

        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (HttpMethods.IsDelete(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            if (!HttpMethods.IsPost(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;
            }

            using var reader = new StreamReader(ctx.Request.Body);
            var body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var method = root.GetProperty("method").GetString();

            int status;
            string? sessionToSet = null;
            string? contentType = null;
            string responseBody = "";

            lock (gate)
            {
                switch (method)
                {
                    case "initialize":
                        gen++;
                        initCount++;
                        validSession = $"sess-{gen}";
                        sessionToSet = validSession;
                        status = StatusCodes.Status200OK;
                        contentType = "application/json";
                        responseBody =
                            $"{{\"jsonrpc\":\"2.0\",\"id\":{root.GetProperty("id").GetRawText()},\"result\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"serverInfo\":{{\"name\":\"test\",\"version\":\"1\"}}}}}}";
                        break;
                    case "notifications/initialized":
                        notifyCount++;
                        status = StatusCodes.Status202Accepted;
                        break;
                    default:
                        if (ctx.Request.Headers["Mcp-Session-Id"].ToString() != validSession)
                        {
                            status = StatusCodes.Status404NotFound;
                        }
                        else
                        {
                            // Invalidate after 1 call to simulate Cloud Run redeploy.
                            validSession = "";
                            status = StatusCodes.Status200OK;
                            contentType = "application/json";
                            responseBody = $"{{\"jsonrpc\":\"2.0\",\"id\":{root.GetProperty("id").GetRawText()},\"result\":{{\"echoedMethod\":\"{method}\"}}}}";
                        }
                        break;
                }
            }

            if (sessionToSet is not null)
            {
                ctx.Response.Headers["Mcp-Session-Id"] = sessionToSet;
            }
            ctx.Response.StatusCode = status;
            if (contentType is not null)
            {
                ctx.Response.ContentType = contentType;
                await ctx.Response.WriteAsync(responseBody);
            }
        });

        await using var server = app;
        using var client = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}""" + "\n" +
            """{"jsonrpc":"2.0","method":"notifications/initialized"}""" + "\n" +
            """{"jsonrpc":"2.0","id":2,"method":"tools/list"}""" + "\n" +
            """{"jsonrpc":"2.0","id":3,"method":"tools/call"}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/mcp",
            client,
            timeout: TimeSpan.FromSeconds(5),
            inputStream: input,
            outputStream: output);

        using var cts = new CancellationTokenSource();
        await bridge.RunAsync(cts.Token);
        await bridge.ShutdownAsync(CancellationToken.None);
        cts.Cancel();

        var lines = ParseOutputLines(output.GetText());
        Assert.Equal(3, lines.Count);
        var byId = lines.ToDictionary(m => m.GetProperty("id").GetInt32());
        Assert.Equal("tools/list", byId[2].GetProperty("result").GetProperty("echoedMethod").GetString());
        Assert.Equal("tools/call", byId[3].GetProperty("result").GetProperty("echoedMethod").GetString());
        Assert.Equal(2, initCount);
        Assert.Equal(2, notifyCount);
    }

    [Fact]
    public async Task Bridge_SurfacesUpstreamAuthFailureAsJsonRpcError()
    {
        var (app, baseUrl) = await StartTestServerAsync(ctx =>
        {
            ctx.Response.Headers[IapClassifier.GeneratedResponseHeader] = "true";
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return ctx.Response.WriteAsync("Invalid IAP credentials");
        });

        await using var server = app;
        using var client = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream("""{"jsonrpc":"2.0","id":7,"method":"initialize"}""" + "\n");

        await using var bridge = new McpBridge(baseUrl, client, timeout: TimeSpan.FromSeconds(2), inputStream: input, outputStream: output);
        using var cts = new CancellationTokenSource();
        await bridge.RunAsync(cts.Token);
        cts.Cancel();

        var lines = ParseOutputLines(output.GetText());
        Assert.Single(lines);
        Assert.Equal(7, lines[0].GetProperty("id").GetInt32());
        Assert.True(lines[0].TryGetProperty("error", out _));
    }

    [Fact]
    public async Task Bridge_AutoDetectFallsBackToLegacySse()
    {
        var outboundEvents = Channel.CreateUnbounded<string>();

        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (ctx.Request.Path == "/sse")
            {
                if (HttpMethods.IsPost(ctx.Request.Method))
                {
                    ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    return;
                }

                if (HttpMethods.IsGet(ctx.Request.Method))
                {
                    ctx.Response.ContentType = "text/event-stream";
                    await ctx.Response.WriteAsync("event: endpoint\ndata: /messages?sessionId=legacy-1\n\n");
                    await ctx.Response.Body.FlushAsync();

                    try
                    {
                        await foreach (var payload in outboundEvents.Reader.ReadAllAsync(ctx.RequestAborted))
                        {
                            await ctx.Response.WriteAsync($"event: message\ndata: {payload}\n\n");
                            await ctx.Response.Body.FlushAsync();
                        }
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    return;
                }
            }

            if (ctx.Request.Path == "/messages" && HttpMethods.IsPost(ctx.Request.Method))
            {
                Assert.Equal("legacy-1", ctx.Request.Query["sessionId"].ToString());
                using var reader = new StreamReader(ctx.Request.Body);
                var body = await reader.ReadToEndAsync();
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                var method = root.GetProperty("method").GetString();

                if (root.TryGetProperty("id", out var idProp))
                {
                    var responseJson = method == "initialize"
                        ? $"{{\"jsonrpc\":\"2.0\",\"id\":{idProp.GetRawText()},\"result\":{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},\"serverInfo\":{{\"name\":\"legacy-sse\",\"version\":\"1.0\"}}}}}}"
                        : $"{{\"jsonrpc\":\"2.0\",\"id\":{idProp.GetRawText()},\"result\":{{\"legacyEcho\":\"{method}\"}}}}";
                    await outboundEvents.Writer.WriteAsync(responseJson);
                }

                ctx.Response.StatusCode = StatusCodes.Status202Accepted;
                return;
            }

            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        });

        await using var server = app;
        using var client = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}""" + "\n" +
            """{"jsonrpc":"2.0","method":"notifications/initialized"}""" + "\n" +
            """{"jsonrpc":"2.0","id":2,"method":"tools/list"}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/sse",
            client,
            transportMode: HttpTransportMode.AutoDetect,
            timeout: TimeSpan.FromSeconds(5),
            inputStream: input,
            outputStream: output);

        using var cts = new CancellationTokenSource();
        await bridge.RunAsync(cts.Token);

        outboundEvents.Writer.TryComplete();
        await bridge.ShutdownAsync(CancellationToken.None);
        cts.Cancel();

        var lines = ParseOutputLines(output.GetText());
        Assert.Equal(2, lines.Count);
        var byId = lines.ToDictionary(m => m.GetProperty("id").GetInt32());
        Assert.Equal("2024-11-05", byId[1].GetProperty("result").GetProperty("protocolVersion").GetString());
        Assert.Equal("tools/list", byId[2].GetProperty("result").GetProperty("legacyEcho").GetString());
    }

    [Fact]
    public async Task Bridge_LegacySseTimeoutFiresWhenNoReplyArrives()
    {
        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (ctx.Request.Path == "/sse" && HttpMethods.IsGet(ctx.Request.Method))
            {
                ctx.Response.ContentType = "text/event-stream";
                await ctx.Response.WriteAsync("event: endpoint\ndata: /messages?sessionId=legacy-timeout\n\n");
                await ctx.Response.Body.FlushAsync();

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), ctx.RequestAborted);
                }
                catch (OperationCanceledException)
                {
                }
                return;
            }

            if (ctx.Request.Path == "/messages" && HttpMethods.IsPost(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status202Accepted;
                return;
            }

            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        });

        await using var server = app;
        using var client = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };
        var output = new SyncMemoryStream();
        using var input = Utf8Stream(
            """{"jsonrpc":"2.0","id":11,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}""" + "\n");

        await using var bridge = new McpBridge(
            baseUrl + "/sse",
            client,
            transportMode: HttpTransportMode.Sse,
            timeout: TimeSpan.FromMilliseconds(150),
            inputStream: input,
            outputStream: output);

        await bridge.RunAsync(CancellationToken.None);

        var lines = ParseOutputLines(output.GetText());
        Assert.Single(lines);
        Assert.Equal(11, lines[0].GetProperty("id").GetInt32());
        var errMsg = lines[0].GetProperty("error").GetProperty("message").GetString()!;
        Assert.Contains("timed out", errMsg);
    }

    [Fact]
    public async Task Bridge_EndToEndWithSdkMcpClientAndPipe()
    {
        var deleted = false;
        var (app, baseUrl) = await StartTestServerAsync(async ctx =>
        {
            if (HttpMethods.IsGet(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return;
            }

            if (HttpMethods.IsDelete(ctx.Request.Method))
            {
                deleted = ctx.Request.Headers["Mcp-Session-Id"].ToString() == "sdk-sess-1";
                ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            using var reader = new StreamReader(ctx.Request.Body);
            var body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var method = root.GetProperty("method").GetString();

            if (!root.TryGetProperty("id", out var idProp))
            {
                ctx.Response.StatusCode = StatusCodes.Status202Accepted;
                return;
            }

            var idRaw = idProp.GetRawText();
            if (method == "server/discover")
            {
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(
                    $"{{\"jsonrpc\":\"2.0\",\"id\":{idRaw},\"error\":{{\"code\":-32601,\"message\":\"Method not found\"}}}}");
                return;
            }

            ctx.Response.Headers["Mcp-Session-Id"] = "sdk-sess-1";
            ctx.Response.ContentType = "application/json";

            var resultJson = method switch
            {
                "initialize" => """{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"upstream-mcp","version":"1.0.0"}}""",
                "tools/list" => """{"tools":[{"name":"echo","description":"Echo text","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}]}""",
                "tools/call" => $"{{\"content\":[{{\"type\":\"text\",\"text\":{root.GetProperty("params").GetProperty("arguments").GetProperty("text").GetRawText()}}}]}}",
                _ => "{}",
            };

            await ctx.Response.WriteAsync($"{{\"jsonrpc\":\"2.0\",\"id\":{idRaw},\"result\":{resultJson}}}");
        });

        await using var server = app;
        using var httpClient = new HttpClient(new StubAuthInjectHandler()) { Timeout = Timeout.InfiniteTimeSpan };

        var clientToBridge = new Pipe();
        var bridgeToClient = new Pipe();

        await using var bridge = new McpBridge(
            baseUrl + "/mcp",
            httpClient,
            timeout: TimeSpan.FromSeconds(5),
            inputStream: clientToBridge.Reader.AsStream(),
            outputStream: bridgeToClient.Writer.AsStream());

        var bridgeTask = bridge.RunAsync(CancellationToken.None);

        await using (var sdkClient = await McpClient.CreateAsync(
            new StreamClientTransport(clientToBridge.Writer.AsStream(), bridgeToClient.Reader.AsStream())))
        {
            Assert.Equal("upstream-mcp", sdkClient.ServerInfo?.Name);
            var tools = await sdkClient.ListToolsAsync();
            Assert.Single(tools);
            Assert.Equal("echo", tools[0].Name);

            var callResult = await sdkClient.CallToolAsync(
                "echo",
                new Dictionary<string, object?> { ["text"] = "hello-iap-auther" });
            Assert.False(callResult.IsError ?? false);
            var textBlock = Assert.IsType<TextContentBlock>(Assert.Single(callResult.Content));
            Assert.Equal("hello-iap-auther", textBlock.Text);
        }

        clientToBridge.Writer.Complete();
        await bridgeTask.WaitAsync(TimeSpan.FromSeconds(5));
        await bridge.ShutdownAsync(CancellationToken.None);
        bridgeToClient.Writer.Complete();

        Assert.True(deleted);
    }

    [Fact]
    public async Task LocalStreamTransport_ParseErrorRecoversRequestId()
    {
        var output = new SyncMemoryStream();
        using var input = Utf8Stream("""{"jsonrpc":"2.0","id":99,"params":not-valid-json}""" + "\n");
        await using var transport = new LocalStreamTransport(input, output, "test", leaveOpen: true);

        await foreach (var _ in transport.MessageReader.ReadAllAsync())
        {
        }

        // Wait briefly for error write if still flushing before EOF completed
        var lines = ParseOutputLines(output.GetText());
        Assert.Single(lines);
        Assert.Equal(99, lines[0].GetProperty("id").GetInt32());
        Assert.Equal(-32700, lines[0].GetProperty("error").GetProperty("code").GetInt32());
    }

    [Theory]
    [InlineData("auto", HttpTransportMode.AutoDetect)]
    [InlineData("streamable-http", HttpTransportMode.StreamableHttp)]
    [InlineData("streamable", HttpTransportMode.StreamableHttp)]
    [InlineData("sse", HttpTransportMode.Sse)]
    public void McpProxyCommand_TryParseTransportMode_ValidValues(string raw, HttpTransportMode expected)
    {
        Assert.True(McpProxyCommand.TryParseTransportMode(raw, out var mode));
        Assert.Equal(expected, mode);
    }

    [Fact]
    public void McpProxyCommand_TryParseTransportMode_InvalidValueReturnsFalse()
    {
        Assert.False(McpProxyCommand.TryParseTransportMode("websocket", out _));
    }
}
