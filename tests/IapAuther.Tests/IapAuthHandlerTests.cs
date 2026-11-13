using System.Net;
using System.Text;
using IapAuther.Auth;
using IapAuther.Iap;

namespace IapAuther.Tests;

public sealed class IapAuthHandlerTests
{
    private sealed class StubTokenSource(Func<int, ValueTask<string>> mint) : ITokenSource
    {
        public int Calls { get; private set; }

        public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
        {
            Calls++;
            return mint(Calls);
        }
    }

    private sealed class StubHttpHandler(Func<HttpRequestMessage, int, Task<HttpResponseMessage>> handle) : HttpMessageHandler
    {
        public int Attempts { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Attempts++;
            return handle(request, Attempts);
        }
    }

    [Fact]
    public async Task AttachesProxyAuthorizationAndDownstreamAuthorization()
    {
        string? gotProxy = null;
        string? gotAuth = null;

        var inner = new StubHttpHandler((req, _) =>
        {
            gotProxy = req.Headers.ProxyAuthorization?.ToString();
            gotAuth = req.Headers.TryGetValues("Authorization", out var vals) ? vals.FirstOrDefault() : null;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var cached = new CachedTokenSource(
            new StubTokenSource(_ => ValueTask.FromResult(CachedTokenSourceTests.MakeJwt(DateTimeOffset.UtcNow.AddHours(1)))),
            TimeSpan.FromMinutes(5));

        using var client = new HttpClient(new IapAuthHandler(cached, "aud", "Bearer app-token", innerHandler: inner));
        using var resp = await client.PostAsync("https://example.invalid/mcp", new StringContent("{}", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.NotNull(gotProxy);
        Assert.StartsWith("Bearer ey", gotProxy);
        Assert.Equal("Bearer app-token", gotAuth);
    }

    [Fact]
    public async Task RetriesOnceOn401AndReplaysBody()
    {
        var bodies = new List<string>();
        var inner = new StubHttpHandler(async (req, attempt) =>
        {
            var body = req.Content is not null ? await req.Content.ReadAsStringAsync() : "";
            bodies.Add(body);
            if (attempt == 1)
            {
                var unauth = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Invalid IAP credentials"),
                };
                unauth.Headers.TryAddWithoutValidation(IapClassifier.GeneratedResponseHeader, "true");
                return unauth;
            }
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        var stub = new StubTokenSource(_ => ValueTask.FromResult(CachedTokenSourceTests.MakeJwt(DateTimeOffset.UtcNow.AddHours(1))));
        var cached = new CachedTokenSource(stub, TimeSpan.FromMinutes(5));

        using var client = new HttpClient(new IapAuthHandler(cached, "aud", innerHandler: inner));
        using var resp = await client.PostAsync("https://example.invalid/mcp", new StringContent("""{"id":1}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(2, inner.Attempts);
        Assert.Equal(2, stub.Calls);
        Assert.Equal(["""{"id":1}""", """{"id":1}"""], bodies);
    }

    [Fact]
    public async Task GivesUpAfterSecond401()
    {
        var inner = new StubHttpHandler((_, _) =>
        {
            var unauth = new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("Invalid IAP credentials: audience mismatch"),
            };
            unauth.Headers.TryAddWithoutValidation(IapClassifier.GeneratedResponseHeader, "true");
            return Task.FromResult(unauth);
        });

        var cached = new CachedTokenSource(
            new StubTokenSource(_ => ValueTask.FromResult(CachedTokenSourceTests.MakeJwt(DateTimeOffset.UtcNow.AddHours(1)))),
            TimeSpan.FromMinutes(5));

        using var client = new HttpClient(new IapAuthHandler(cached, "https://x.a.run.app", innerHandler: inner));
        using var resp = await client.PostAsync("https://example.invalid/mcp", new StringContent("{}"));

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Equal(2, inner.Attempts);
    }

    [Fact]
    public async Task Treats302ToGoogleSignInAsAuthFailureAndRetriesOnce()
    {
        var inner = new StubHttpHandler((_, attempt) =>
        {
            if (attempt == 1)
            {
                var redir = new HttpResponseMessage(HttpStatusCode.Found);
                redir.Headers.Location = new Uri("https://accounts.google.com/o/oauth2/v2/auth?x=y");
                return Task.FromResult(redir);
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var cached = new CachedTokenSource(
            new StubTokenSource(_ => ValueTask.FromResult(CachedTokenSourceTests.MakeJwt(DateTimeOffset.UtcNow.AddHours(1)))),
            TimeSpan.FromMinutes(5));

        using var client = new HttpClient(new IapAuthHandler(cached, "aud", innerHandler: inner));
        using var resp = await client.PostAsync("https://example.invalid/mcp", new StringContent("{}"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(2, inner.Attempts);
    }

    [Fact]
    public async Task PropagatesTokenMintFailure()
    {
        var inner = new StubHttpHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var cached = new CachedTokenSource(
            new StubTokenSource(_ => ValueTask.FromException<string>(new TimeoutException("mint timed out"))),
            TimeSpan.FromMinutes(1));

        using var client = new HttpClient(new IapAuthHandler(cached, "aud", innerHandler: inner));
        var ex = await Assert.ThrowsAsync<AuthException>(() => client.GetAsync("https://example.invalid/mcp"));
        Assert.Contains("Obtaining IAP token failed", ex.Message);
    }
}
