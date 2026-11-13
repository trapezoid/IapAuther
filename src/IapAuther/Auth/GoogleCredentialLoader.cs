using Google.Apis.Auth.OAuth2;

namespace IapAuther.Auth;

internal static class GoogleCredentialLoader
{
    public static async Task<GoogleCredential> LoadAsync(string? credentialFile, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(credentialFile))
        {
            if (!File.Exists(credentialFile))
            {
                throw new AuthException($"Credential file not found: {credentialFile}");
            }
            var cred = await CredentialFactory.FromFileAsync<Google.Apis.Auth.OAuth2.ICredential>(credentialFile, cancellationToken)
                .ConfigureAwait(false);
            return cred switch
            {
                ServiceAccountCredential sa => sa.ToGoogleCredential(),
                UserCredential user => user.ToGoogleCredential(),
                ImpersonatedCredential imp => imp.ToGoogleCredential(),
                AwsExternalAccountCredential aws => aws.ToGoogleCredential(),
                FileSourcedExternalAccountCredential fileExt => fileExt.ToGoogleCredential(),
                UrlSourcedExternalAccountCredential urlExt => urlExt.ToGoogleCredential(),
                ProgrammaticExternalAccountCredential progExt => progExt.ToGoogleCredential(),
                ExternalAccountAuthorizedUserCredential extUser => extUser.ToGoogleCredential(),
                ComputeCredential compute => compute.ToGoogleCredential(),
                _ => throw new AuthException($"Unsupported credential type '{cred.GetType().Name}' in {credentialFile}"),
            };
        }

        try
        {
            return await GoogleCredential.GetApplicationDefaultAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or FileNotFoundException)
        {
            throw new AuthException($"Failed to load Application Default Credentials: {ex.Message}", ex);
        }
    }
}
