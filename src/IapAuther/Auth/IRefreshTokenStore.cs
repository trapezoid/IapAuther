namespace IapAuther.Auth;

internal interface IRefreshTokenStore
{
    string BackendName { get; }

    ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default);

    ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default);

    ValueTask DeleteAsync(string clientId, CancellationToken cancellationToken = default);
}
