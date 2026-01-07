using PassKeySample.Api.Models;

namespace PassKeySample.Api.Services.WebAuthn;

/// <summary>
/// Defines the contract for storing and retrieving WebAuthn credentials (passkeys).
/// Implementations handle persistence of credential data for authentication verification.
/// </summary>
public interface IWebAuthnCredentialStore
{
    /// <summary>
    /// Stores a new WebAuthn credential for a user.
    /// </summary>
    /// <param name="credential">The credential to store, containing public key and metadata.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    Task StoreCredentialAsync(WebAuthnCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all WebAuthn credentials registered for a specific user.
    /// </summary>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>A list of all credentials for the user, or an empty list if none exist.</returns>
    Task<List<WebAuthnCredential>> GetCredentialsAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific credential by user ID and credential ID.
    /// </summary>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <param name="credentialId">The unique identifier of the credential (from the authenticator).</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The credential if found, or null if not found.</returns>
    Task<WebAuthnCredential?> GetCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the signature counter for a credential after successful authentication.
    /// The counter is used to detect cloned authenticators (replay attack prevention).
    /// </summary>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <param name="credentialId">The unique identifier of the credential.</param>
    /// <param name="counter">The new counter value from the authenticator.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    Task UpdateCounterAsync(string userId, byte[] credentialId, uint counter, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a specific credential for a user.
    /// </summary>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <param name="credentialId">The unique identifier of the credential to delete.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    Task DeleteCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default);
}

