using IapAuther.Logging;

namespace IapAuther.Auth;

internal sealed record AuthConfig
{
    public CredentialMode Mode { get; init; } = CredentialMode.Auto;
    public required string Audience { get; init; }
    public string? ImpersonateServiceAccount { get; init; }
    public string? CredentialFile { get; init; }
    public string? OAuthClientId { get; init; }
    public string? OAuthClientSecret { get; init; }
    public TokenStoreMode TokenStore { get; init; } = TokenStoreMode.Auto;
    public TimeSpan RefreshMargin { get; init; } = TimeSpan.FromMinutes(5);
    public bool NoBrowser { get; init; }
    public StderrLogger? Logger { get; init; }
}
