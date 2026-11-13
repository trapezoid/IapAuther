namespace IapAuther.Auth;

internal sealed class CredentialStoreUnavailableException : Exception
{
    public CredentialStoreUnavailableException(string message)
        : base(message)
    {
    }

    public CredentialStoreUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
