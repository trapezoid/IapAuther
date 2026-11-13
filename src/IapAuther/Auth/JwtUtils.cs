using System.Text;
using System.Text.Json;

namespace IapAuther.Auth;

internal sealed record JwtClaims(
    DateTimeOffset ExpiresAt,
    string? Audience,
    string? Issuer,
    string? Subject,
    string? Email);

internal static class JwtUtils
{
    public static DateTimeOffset ExtractExpiry(string jwt) => ExtractClaims(jwt).ExpiresAt;

    public static JwtClaims ExtractClaims(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new FormatException("Token is not a valid JWT (expected 3 dot-separated segments).");
        }

        byte[] payloadBytes;
        try
        {
            payloadBytes = DecodeBase64Url(parts[1]);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new FormatException($"Decoding JWT claims failed: {ex.Message}", ex);
        }

        using var doc = JsonDocument.Parse(payloadBytes);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("JWT payload is not a JSON object.");
        }

        if (!root.TryGetProperty("exp", out var expProp) || !expProp.TryGetInt64(out var expUnix) || expUnix <= 0)
        {
            throw new FormatException("JWT is missing a valid 'exp' claim.");
        }

        var aud = root.TryGetProperty("aud", out var audProp) && audProp.ValueKind == JsonValueKind.String
            ? audProp.GetString()
            : null;
        var iss = root.TryGetProperty("iss", out var issProp) && issProp.ValueKind == JsonValueKind.String
            ? issProp.GetString()
            : null;
        var sub = root.TryGetProperty("sub", out var subProp) && subProp.ValueKind == JsonValueKind.String
            ? subProp.GetString()
            : null;
        var email = root.TryGetProperty("email", out var emailProp) && emailProp.ValueKind == JsonValueKind.String
            ? emailProp.GetString()
            : null;

        return new JwtClaims(DateTimeOffset.FromUnixTimeSeconds(expUnix), aud, iss, sub, email);
    }

    public static string EncodeBase64Url(ReadOnlySpan<byte> data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    public static string EncodeBase64UrlUtf8(string text) =>
        EncodeBase64Url(Encoding.UTF8.GetBytes(text));

    public static byte[] DecodeBase64Url(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
            case 1:
                throw new FormatException("Invalid base64url length.");
        }
        return Convert.FromBase64String(padded);
    }
}
