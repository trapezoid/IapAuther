namespace IapAuther.Auth;

internal enum TokenStoreMode
{
    Auto,
    Os,
    File,
}

internal static class TokenStoreModeExtensions
{
    public static bool TryParse(string? value, out TokenStoreMode mode)
    {
        switch (value?.Trim().ToLowerInvariant())
        {
            case null or "" or "auto":
                mode = TokenStoreMode.Auto;
                return true;
            case "os" or "native" or "keychain" or "keyring":
                mode = TokenStoreMode.Os;
                return true;
            case "file":
                mode = TokenStoreMode.File;
                return true;
            default:
                mode = TokenStoreMode.Auto;
                return false;
        }
    }

    public static string ToCliString(this TokenStoreMode mode) => mode switch
    {
        TokenStoreMode.Auto => "auto",
        TokenStoreMode.Os => "os",
        TokenStoreMode.File => "file",
        _ => "auto",
    };
}
