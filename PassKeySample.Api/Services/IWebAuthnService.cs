using Fido2NetLib;
using Fido2NetLib.Objects;

namespace PassKeySample.Api.Services;

public interface IWebAuthnService
{
    Task<CredentialCreateOptions> GenerateRegistrationOptionsAsync(string userId, string username, CancellationToken cancellationToken = default);
    Task<object> VerifyRegistrationAsync(AuthenticatorAttestationRawResponse attestationResponse, CredentialCreateOptions originalOptions, CancellationToken cancellationToken = default);
    Task<AssertionOptions> GenerateAssertionOptionsAsync(string userId, List<object>? allowedCredentials = null, CancellationToken cancellationToken = default);
    Task<object> VerifyAssertionAsync(AuthenticatorAssertionRawResponse assertionResponse, AssertionOptions originalOptions, byte[] storedCredentialId, byte[] storedPublicKey, uint storedCounter, CancellationToken cancellationToken = default);
}
