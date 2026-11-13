using IapAuther.Auth;
using IapAuther.Iap;

namespace IapAuther.Tests;

public sealed class AudienceResolverTests
{
    [Theory]
    [InlineData("signjwt", "https://svc-xxxx-an.a.run.app/mcp", "https://svc-xxxx-an.a.run.app/mcp")]
    [InlineData("signjwt", "https://svc-xxxx-an.a.run.app/mcp%2Fv1", "https://svc-xxxx-an.a.run.app/mcp%2Fv1")]
    [InlineData("signjwt", "https://svc-xxxx-an.a.run.app/mcp?foo=bar", "https://svc-xxxx-an.a.run.app/mcp")]
    [InlineData("signjwt", "https://svc-xxxx-an.a.run.app/mcp#frag", "https://svc-xxxx-an.a.run.app/mcp")]
    [InlineData("signjwt", "https://svc-xxxx-an.a.run.app", "https://svc-xxxx-an.a.run.app/*")]
    [InlineData("signjwt", "https://svc-xxxx-an.a.run.app/", "https://svc-xxxx-an.a.run.app/*")]
    [InlineData("adc", "https://svc-xxxx-an.a.run.app/mcp", "https://svc-xxxx-an.a.run.app")]
    [InlineData("impersonate", "https://svc-xxxx-an.a.run.app/mcp", "https://svc-xxxx-an.a.run.app")]
    [InlineData("oauth", "https://svc-xxxx-an.a.run.app/mcp", "https://svc-xxxx-an.a.run.app")]
    [InlineData("auto", "https://svc-xxxx-an.a.run.app/mcp", "https://svc-xxxx-an.a.run.app")]
    public void ResolveDefaultAudience_MatchesExpectedRules(string modeRaw, string upstream, string expected)
    {
        Assert.True(CredentialModeExtensions.TryParse(modeRaw, out var mode));
        var uri = new Uri(upstream, UriKind.Absolute);
        var actual = AudienceResolver.ResolveDefaultAudience(mode, uri);
        Assert.Equal(expected, actual);
    }
}
