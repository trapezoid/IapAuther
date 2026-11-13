using IapAuther.Auth;

namespace IapAuther.Iap;

internal static class AudienceResolver
{
    public static string ResolveDefaultAudience(CredentialMode mode, Uri upstreamUri)
    {
        var origin = upstreamUri.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped);
        if (mode != CredentialMode.SignJwt)
        {
            return origin;
        }

        // Preserve percent-encoded paths verbatim (e.g. /mcp%2Fv1) while stripping query and fragment.
        var escapedPath = upstreamUri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        if (string.IsNullOrEmpty(escapedPath) || escapedPath == "/")
        {
            return origin + "/*";
        }

        return origin + "/" + escapedPath.TrimStart('/');
    }
}
