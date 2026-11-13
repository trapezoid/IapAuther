using System.Text.Json;
using IapAuther.Auth;

namespace IapAuther.Tests;

public sealed class CachedTokenSourceTests
{
    internal static string MakeJwt(DateTimeOffset exp)
    {
        var header = JwtUtils.EncodeBase64UrlUtf8("""{"alg":"RS256"}""");
        var payload = JwtUtils.EncodeBase64UrlUtf8(JsonSerializer.Serialize(new
        {
            exp = exp.ToUnixTimeSeconds(),
            aud = "test",
        }));
        return $"{header}.{payload}.sig";
    }

    private sealed class FakeTokenSource(Func<int, ValueTask<string>> mint) : ITokenSource
    {
        public int Calls { get; private set; }

        public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
        {
            Calls++;
            return mint(Calls);
        }
    }

    [Fact]
    public async Task ReusesTokenUntilMarginThenRefreshes()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000);
        var exp = now.AddHours(1);
        var fake = new FakeTokenSource(_ => ValueTask.FromResult(MakeJwt(exp)));
        var cached = new CachedTokenSource(fake, TimeSpan.FromMinutes(5), () => now);

        for (var i = 0; i < 3; i++)
        {
            await cached.GetTokenAsync();
        }
        Assert.Equal(1, fake.Calls);

        now = exp.AddMinutes(-4);
        exp = now.AddHours(1);
        await cached.GetTokenAsync();
        Assert.Equal(2, fake.Calls);
    }

    [Fact]
    public async Task InvalidateForcesRemint()
    {
        var fake = new FakeTokenSource(_ => ValueTask.FromResult(MakeJwt(DateTimeOffset.UtcNow.AddHours(1))));
        var cached = new CachedTokenSource(fake, TimeSpan.FromMinutes(5));

        await cached.GetTokenAsync();
        cached.Invalidate();
        await cached.GetTokenAsync();

        Assert.Equal(2, fake.Calls);
    }

    [Fact]
    public async Task RejectsMalformedJwt()
    {
        var fake = new FakeTokenSource(_ => ValueTask.FromResult("not-a-jwt"));
        var cached = new CachedTokenSource(fake, TimeSpan.FromMinutes(1));

        await Assert.ThrowsAsync<AuthException>(() => cached.GetTokenAsync().AsTask());
    }

    [Fact]
    public async Task PropagatesMintError()
    {
        var fake = new FakeTokenSource(n => ValueTask.FromException<string>(new InvalidOperationException($"boom {n}")));
        var cached = new CachedTokenSource(fake, TimeSpan.FromMinutes(1));

        await Assert.ThrowsAsync<InvalidOperationException>(() => cached.GetTokenAsync().AsTask());
    }
}
