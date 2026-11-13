namespace IapAuther.Auth;

internal interface ITokenSource
{
    ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default);
}
