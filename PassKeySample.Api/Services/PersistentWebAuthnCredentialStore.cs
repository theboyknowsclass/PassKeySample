using PassKeySample.Api.Models;

namespace PassKeySample.Api.Services;

/// <summary>
/// Base implementation for persistent WebAuthn credential storage.
/// Implement this class to provide database-backed or other persistent storage.
/// </summary>
public abstract class PersistentWebAuthnCredentialStore : IWebAuthnCredentialStore
{
    protected readonly ILogger<PersistentWebAuthnCredentialStore> Logger;

    protected PersistentWebAuthnCredentialStore(ILogger<PersistentWebAuthnCredentialStore> logger)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Stores a WebAuthn credential persistently.
    /// </summary>
    public abstract Task StoreCredentialAsync(WebAuthnCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all credentials for a given user.
    /// </summary>
    public abstract Task<List<WebAuthnCredential>> GetCredentialsAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific credential by user ID and credential ID.
    /// </summary>
    public abstract Task<WebAuthnCredential?> GetCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the signature counter for a credential (used for replay attack prevention).
    /// </summary>
    public abstract Task UpdateCounterAsync(string userId, byte[] credentialId, uint counter, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a credential for a user.
    /// </summary>
    public abstract Task DeleteCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default);
}

