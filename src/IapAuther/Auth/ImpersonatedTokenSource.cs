using Google.Apis.Auth.OAuth2;
using Google.Apis.IAMCredentials.v1;
using Google.Apis.IAMCredentials.v1.Data;
using Google.Apis.Services;

namespace IapAuther.Auth;

internal sealed class ImpersonatedTokenSource : ITokenSource, IDisposable
{
    private readonly IAMCredentialsService _iamService;
    private readonly string _targetServiceAccount;
    private readonly string _audience;

    private ImpersonatedTokenSource(
        IAMCredentialsService iamService,
        string targetServiceAccount,
        string audience)
    {
        _iamService = iamService;
        _targetServiceAccount = targetServiceAccount;
        _audience = audience;
    }

    public static async Task<ImpersonatedTokenSource> CreateAsync(
        string targetServiceAccount,
        string audience,
        string? credentialFile,
        CancellationToken cancellationToken)
    {
        var baseCredential = await GoogleCredentialLoader.LoadAsync(credentialFile, cancellationToken)
            .ConfigureAwait(false);

        if (baseCredential.IsCreateScopedRequired)
        {
            baseCredential = baseCredential.CreateScoped(IAMCredentialsService.Scope.CloudPlatform);
        }

        var iamService = new IAMCredentialsService(new BaseClientService.Initializer
        {
            HttpClientInitializer = baseCredential,
            ApplicationName = "IapAuther",
        });

        return new ImpersonatedTokenSource(iamService, targetServiceAccount, audience);
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var request = new GenerateIdTokenRequest
            {
                Audience = _audience,
                IncludeEmail = true,
            };
            var resourceName = $"projects/-/serviceAccounts/{_targetServiceAccount}";
            var response = await _iamService.Projects.ServiceAccounts
                .GenerateIdToken(request, resourceName)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            if (string.IsNullOrEmpty(response.Token))
            {
                throw new AuthException($"IAM Credentials API returned an empty ID token for {_targetServiceAccount}.");
            }
            return response.Token;
        }
        catch (Exception ex) when (ex is not AuthException && ex is not OperationCanceledException)
        {
            throw new AuthException(
                $"Impersonating {_targetServiceAccount} failed: {ex.Message} (does the caller have roles/iam.serviceAccountTokenCreator on it?)",
                ex);
        }
    }

    public void Dispose() => _iamService.Dispose();
}
