namespace IapAuther.Auth;

internal enum CredentialMode
{
    Auto,
    Adc,
    Impersonate,
    OAuth,
    SignJwt,
}

internal static class CredentialModeExtensions
{
    public static bool TryParse(string? value, out CredentialMode mode)
    {
        switch (value?.Trim().ToLowerInvariant())
        {
            case null or "" or "auto":
                mode = CredentialMode.Auto;
                return true;
            case "adc":
                mode = CredentialMode.Adc;
                return true;
            case "impersonate":
                mode = CredentialMode.Impersonate;
                return true;
            case "oauth":
                mode = CredentialMode.OAuth;
                return true;
            case "signjwt":
                mode = CredentialMode.SignJwt;
                return true;
            default:
                mode = CredentialMode.Auto;
                return false;
        }
    }

    public static string ToCliString(this CredentialMode mode) => mode switch
    {
        CredentialMode.Auto => "auto",
        CredentialMode.Adc => "adc",
        CredentialMode.Impersonate => "impersonate",
        CredentialMode.OAuth => "oauth",
        CredentialMode.SignJwt => "signjwt",
        _ => "auto",
    };
}
