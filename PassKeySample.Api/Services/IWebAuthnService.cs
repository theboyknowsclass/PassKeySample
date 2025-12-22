using Fido2NetLib;

namespace PassKeySample.Api.Services;

public interface IWebAuthnService
{
    Task<CredentialCreateOptions> GenerateRegistrationOptionsAsync(string userId, string username, CancellationToken cancellationToken = default);
    Task<Fido2.CredentialMakeResult> VerifyRegistrationAsync(AuthenticatorAttestationRawResponse attestationResponse, CredentialCreateOptions originalOptions, CancellationToken cancellationToken = default);
    Task<AssertionOptions> GenerateAssertionOptionsAsync(string userId, List<PublicKeyCredentialDescriptor>? allowedCredentials = null, CancellationToken cancellationToken = default);
    Task<Fido2.AssertionVerificationResult> VerifyAssertionAsync(AuthenticatorAssertionRawResponse assertionResponse, AssertionOptions originalOptions, byte[] storedCredentialId, byte[] storedPublicKey, uint storedCounter, CancellationToken cancellationToken = default);
}

