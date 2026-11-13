using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Google.Apis.Auth.OAuth2;
using Google.Apis.IAMCredentials.v1;
using Google.Apis.IAMCredentials.v1.Data;
using Google.Apis.Services;

namespace IapAuther.Auth;

internal sealed class SignJwtTokenSource : ITokenSource, IDisposable
{
    private readonly IAMCredentialsService? _iamService;
    private readonly ServiceAccountCredential? _localServiceAccount;
    private readonly string _serviceAccountEmail;
    private readonly string _audience;
    private readonly Func<DateTimeOffset> _now;

    private SignJwtTokenSource(
        IAMCredentialsService? iamService,
        ServiceAccountCredential? localServiceAccount,
        string serviceAccountEmail,
        string audience,
        Func<DateTimeOffset>? now = null)
    {
        _iamService = iamService;
        _localServiceAccount = localServiceAccount;
        _serviceAccountEmail = serviceAccountEmail;
        _audience = audience;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public static async Task<SignJwtTokenSource> CreateAsync(
        string? targetServiceAccount,
        string audience,
        string? credentialFile,
        CancellationToken cancellationToken)
    {
        var baseCredential = await GoogleCredentialLoader.LoadAsync(credentialFile, cancellationToken)
            .ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(targetServiceAccount))
        {
            if (baseCredential.UnderlyingCredential is ServiceAccountCredential saCred &&
                !string.IsNullOrWhiteSpace(saCred.Id) &&
                saCred.Key is not null)
            {
                return new SignJwtTokenSource(null, saCred, saCred.Id, audience);
            }

            throw new AuthException(
                "--credentials=signjwt requires --impersonate-service-account (the target service account to sign as), " +
                "or a service account JSON key via ADC / --credential-file.");
        }

        if (baseCredential.IsCreateScopedRequired)
        {
            baseCredential = baseCredential.CreateScoped(IAMCredentialsService.Scope.CloudPlatform);
        }

        var iamService = new IAMCredentialsService(new BaseClientService.Initializer
        {
            HttpClientInitializer = baseCredential,
            ApplicationName = "IapAuther",
        });

        return new SignJwtTokenSource(iamService, null, targetServiceAccount, audience);
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        var payload = BuildClaimsPayload(_serviceAccountEmail, _audience, _now());

        if (_localServiceAccount is not null)
        {
            return SignLocally(_localServiceAccount, payload);
        }

        try
        {
            var resourceName = $"projects/-/serviceAccounts/{_serviceAccountEmail}";
            var response = await _iamService!.Projects.ServiceAccounts
                .SignJwt(new SignJwtRequest { Payload = payload }, resourceName)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            if (string.IsNullOrEmpty(response.SignedJwt))
            {
                throw new AuthException($"IAM signJwt returned an empty JWT for {_serviceAccountEmail}.");
            }
            return response.SignedJwt;
        }
        catch (Exception ex) when (ex is not AuthException && ex is not OperationCanceledException)
        {
            throw new AuthException(
                $"Signing JWT as {_serviceAccountEmail} failed: {ex.Message} (does the caller have roles/iam.serviceAccountTokenCreator on it?)",
                ex);
        }
    }

    internal static string BuildClaimsPayload(string serviceAccountEmail, string audience, DateTimeOffset now)
    {
        var iat = now.ToUnixTimeSeconds();
        var exp = now.AddHours(1).ToUnixTimeSeconds();
        return JsonSerializer.Serialize(new
        {
            iss = serviceAccountEmail,
            sub = serviceAccountEmail,
            aud = audience,
            iat,
            exp,
        });
    }

    internal static string SignLocally(ServiceAccountCredential credential, string payloadJson)
    {
        var headerJson = string.IsNullOrEmpty(credential.KeyId)
            ? JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT" })
            : JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT", kid = credential.KeyId });

        var signingInput = $"{JwtUtils.EncodeBase64UrlUtf8(headerJson)}.{JwtUtils.EncodeBase64UrlUtf8(payloadJson)}";
        var signature = credential.Key.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return $"{signingInput}.{JwtUtils.EncodeBase64Url(signature)}";
    }

    public void Dispose() => _iamService?.Dispose();
}
