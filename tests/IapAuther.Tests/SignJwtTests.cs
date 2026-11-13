using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Google.Apis.Auth.OAuth2;
using IapAuther.Auth;

namespace IapAuther.Tests;

public sealed class SignJwtTests
{
    [Fact]
    public void BuildClaimsPayload_ContainsRequiredSelfSignedJwtClaims()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var json = SignJwtTokenSource.BuildClaimsPayload(
            "caller@proj.iam.gserviceaccount.com",
            "https://svc.a.run.app/mcp",
            now);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("caller@proj.iam.gserviceaccount.com", root.GetProperty("iss").GetString());
        Assert.Equal("caller@proj.iam.gserviceaccount.com", root.GetProperty("sub").GetString());
        Assert.Equal("https://svc.a.run.app/mcp", root.GetProperty("aud").GetString());
        Assert.Equal(1_700_000_000, root.GetProperty("iat").GetInt64());
        Assert.Equal(1_700_003_600, root.GetProperty("exp").GetInt64());
    }

    [Fact]
    public void SignLocally_ProducesVerifiableRs256Jwt()
    {
        using var rsa = RSA.Create(2048);
        var cred = new ServiceAccountCredential(new ServiceAccountCredential.Initializer("sa@proj.iam.gserviceaccount.com")
        {
            Key = rsa,
            KeyId = "key-id-123",
        });

        var payload = SignJwtTokenSource.BuildClaimsPayload(
            cred.Id,
            "https://svc.a.run.app/*",
            DateTimeOffset.UtcNow);

        var jwt = SignJwtTokenSource.SignLocally(cred, payload);
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        var headerJson = Encoding.UTF8.GetString(JwtUtils.DecodeBase64Url(parts[0]));
        using var headerDoc = JsonDocument.Parse(headerJson);
        Assert.Equal("RS256", headerDoc.RootElement.GetProperty("alg").GetString());
        Assert.Equal("key-id-123", headerDoc.RootElement.GetProperty("kid").GetString());

        var signingInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
        var signature = JwtUtils.DecodeBase64Url(parts[2]);
        Assert.True(rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        var claims = JwtUtils.ExtractClaims(jwt);
        Assert.Equal("sa@proj.iam.gserviceaccount.com", claims.Issuer);
        Assert.Equal("sa@proj.iam.gserviceaccount.com", claims.Subject);
        Assert.Equal("https://svc.a.run.app/*", claims.Audience);
    }
}
