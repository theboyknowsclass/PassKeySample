using Fido2NetLib;
using Fido2NetLib.Objects;

namespace PassKeySample.Api.Services.WebAuthn;

/// <summary>
/// Defines the contract for WebAuthn (FIDO2) operations including passkey registration and authentication.
/// Wraps the FIDO2 library to provide a simplified interface for the application.
/// </summary>
public interface IWebAuthnService
{
    /// <summary>
    /// Generates options for registering a new passkey credential.
    /// These options are sent to the browser to initiate the WebAuthn registration ceremony.
    /// </summary>
    /// <param name="userId">The unique identifier of the user registering the passkey.</param>
    /// <param name="username">The display name/username for the user (shown in authenticator prompts).</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Options containing challenge, relying party info, and user details for registration.</returns>
    Task<CredentialCreateOptions> GenerateRegistrationOptionsAsync(string userId, string username, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the attestation response from the authenticator during registration.
    /// Validates the credential was created correctly and extracts the public key.
    /// </summary>
    /// <param name="attestationResponse">The raw attestation response from the authenticator.</param>
    /// <param name="originalOptions">The original options sent to the browser (for challenge verification).</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The verification result containing the new credential's public key and ID.</returns>
    Task<object> VerifyRegistrationAsync(AuthenticatorAttestationRawResponse attestationResponse, CredentialCreateOptions originalOptions, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates options for authenticating with an existing passkey.
    /// These options are sent to the browser to initiate the WebAuthn authentication ceremony.
    /// </summary>
    /// <param name="userId">The unique identifier of the user attempting to authenticate.</param>
    /// <param name="allowedCredentials">Optional list of allowed credential descriptors to limit which passkeys can be used.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Options containing challenge and allowed credentials for authentication.</returns>
    Task<AssertionOptions> GenerateAssertionOptionsAsync(string userId, List<object>? allowedCredentials = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the assertion response from the authenticator during authentication.
    /// Validates the signature using the stored public key and checks the counter.
    /// </summary>
    /// <param name="assertionResponse">The raw assertion response from the authenticator.</param>
    /// <param name="originalOptions">The original options sent to the browser (for challenge verification).</param>
    /// <param name="storedCredentialId">The stored credential ID to verify against.</param>
    /// <param name="storedPublicKey">The stored public key for signature verification.</param>
    /// <param name="storedCounter">The stored counter value for replay attack detection.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The verification result containing the new counter value.</returns>
    Task<object> VerifyAssertionAsync(AuthenticatorAssertionRawResponse assertionResponse, AssertionOptions originalOptions, byte[] storedCredentialId, byte[] storedPublicKey, uint storedCounter, CancellationToken cancellationToken = default);
}

