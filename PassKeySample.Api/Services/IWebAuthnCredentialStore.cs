using PassKeySample.Api.Models;

namespace PassKeySample.Api.Services;

public interface IWebAuthnCredentialStore
{
    Task StoreCredentialAsync(WebAuthnCredential credential, CancellationToken cancellationToken = default);
    Task<List<WebAuthnCredential>> GetCredentialsAsync(string userId, CancellationToken cancellationToken = default);
    Task<WebAuthnCredential?> GetCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default);
    Task UpdateCounterAsync(string userId, byte[] credentialId, uint counter, CancellationToken cancellationToken = default);
    Task DeleteCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default);
}

