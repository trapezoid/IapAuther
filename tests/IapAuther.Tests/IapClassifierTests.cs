using System.Net;
using System.Text;
using IapAuther.Iap;

namespace IapAuther.Tests;

public sealed class IapClassifierTests
{
    private static HttpResponseMessage MakeResponse(
        HttpStatusCode status,
        Dictionary<string, string>? headers = null,
        string body = "")
    {
        var resp = new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/plain"),
        };
        if (headers is not null)
        {
            foreach (var (k, v) in headers)
            {
                resp.Headers.TryAddWithoutValidation(k, v);
            }
        }
        return resp;
    }

    [Fact]
    public void IsIapResponse_ChecksGeneratedHeader()
    {
        Assert.True(IapClassifier.IsIapResponse(MakeResponse(
            HttpStatusCode.Unauthorized,
            new() { [IapClassifier.GeneratedResponseHeader] = "true" })));

        Assert.False(IapClassifier.IsIapResponse(MakeResponse(HttpStatusCode.Unauthorized)));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, null, true)]
    [InlineData(HttpStatusCode.Found, "https://accounts.google.com/o/oauth2/v2/auth", true)]
    [InlineData(HttpStatusCode.Found, "https://example.com/login", false)]
    [InlineData(HttpStatusCode.Forbidden, null, false)]
    [InlineData(HttpStatusCode.OK, null, false)]
    [InlineData(HttpStatusCode.InternalServerError, null, false)]
    public void IsAuthFailure_ClassifiesResponses(HttpStatusCode status, string? location, bool expected)
    {
        var headers = location is not null ? new Dictionary<string, string> { ["Location"] = location } : null;
        var resp = MakeResponse(status, headers);
        Assert.Equal(expected, IapClassifier.IsAuthFailure(resp));
    }

    [Fact]
    public async Task BuildActionableMessage_HintsSignJwtOnAudienceMismatch()
    {
        var resp = MakeResponse(
            HttpStatusCode.Unauthorized,
            new() { [IapClassifier.GeneratedResponseHeader] = "true" },
            "Invalid IAP credentials: JWT audience doesn't match this application");

        var msg = await IapClassifier.BuildActionableMessageAsync(resp, "https://x.a.run.app");
        Assert.Contains("--audience", msg);
        Assert.Contains("apps.googleusercontent.com", msg);
        Assert.Contains("signjwt", msg);
    }

    [Fact]
    public async Task BuildActionableMessage_HintsRoleOnIapForbidden()
    {
        var resp = MakeResponse(
            HttpStatusCode.Forbidden,
            new() { [IapClassifier.GeneratedResponseHeader] = "true" },
            "access denied");

        var msg = await IapClassifier.BuildActionableMessageAsync(resp, "aud");
        Assert.Contains("iap.httpsResourceAccessor", msg);
    }

    [Fact]
    public async Task BuildActionableMessage_PreservesFullResponseBody()
    {
        const string body = "Invalid IAP credentials: JWT audience doesn't match this application";
        var resp = MakeResponse(HttpStatusCode.Unauthorized, null, body);

        _ = await IapClassifier.BuildActionableMessageAsync(resp, "aud");
        var remaining = await resp.Content.ReadAsStringAsync();

        Assert.Equal(body, remaining);
    }

    [Fact]
    public async Task BuildActionableMessage_HandlesGoogleSignInRedirect()
    {
        var resp = MakeResponse(
            HttpStatusCode.Found,
            new() { ["Location"] = "https://accounts.google.com/x" });

        var msg = await IapClassifier.BuildActionableMessageAsync(resp, "aud");
        Assert.Contains("sign-in", msg);
    }
}
