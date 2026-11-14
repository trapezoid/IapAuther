namespace IapAuther.Auth;

internal interface IRefreshTokenStore
{
    string BackendName { get; }

    ValueTask<string?> LoadAsync(string clientId, CancellationToken cancellationToken = default);

    ValueTask SaveAsync(string clientId, string refreshToken, CancellationToken cancellationToken = default);

    ValueTask<bool> DeleteAsync(string clientId, CancellationToken cancellationToken = default);

    ValueTask<int> ClearAsync(CancellationToken cancellationToken = default);
}
