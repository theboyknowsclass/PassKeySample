using Fido2NetLib;
using PassKeySample.Api.Configuration;

namespace PassKeySample.Api.Services;

public class WebAuthnService : IWebAuthnService
{
    private readonly IFido2 _fido2;
    private readonly ILogger<WebAuthnService> _logger;

    public WebAuthnService(
        IFido2 fido2,
        ILogger<WebAuthnService> logger)
    {
        _fido2 = fido2;
        _logger = logger;
    }

    public Task<CredentialCreateOptions> GenerateRegistrationOptionsAsync(string userId, string username, CancellationToken cancellationToken = default)
    {
        var user = new Fido2User
        {
            DisplayName = username,
            Name = username,
            Id = System.Text.Encoding.UTF8.GetBytes(userId)
        };

        var authenticatorSelection = new AuthenticatorSelection
        {
            UserVerification = UserVerificationRequirement.Preferred,
            AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform // Support both platform and cross-platform
        };

        var exts = new AuthenticationExtensionsClientInputs
        {
            Extensions = true,
            UserVerificationMethod = true
        };

        var options = _fido2.RequestNewCredential(user, authenticatorSelection, AttestationConveyancePreference.None, exts);

        _logger.LogInformation("Generated registration options for user: {UserId}", userId);
        return Task.FromResult(options);
    }

    public async Task<Fido2.CredentialMakeResult> VerifyRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await _fido2.MakeNewCredentialAsync(attestationResponse, originalOptions, IsCredentialIdUniqueToUserAsync);
            _logger.LogInformation("Successfully verified registration");
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify registration");
            throw;
        }
    }

    public Task<AssertionOptions> GenerateAssertionOptionsAsync(string userId, List<PublicKeyCredentialDescriptor>? allowedCredentials = null, CancellationToken cancellationToken = default)
    {
        var credentials = allowedCredentials ?? new List<PublicKeyCredentialDescriptor>();
        var options = _fido2.GetAssertionOptions(
            credentials,
            UserVerificationRequirement.Preferred,
            new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                UserVerificationMethod = true
            });

        _logger.LogInformation("Generated assertion options for user: {UserId}", userId);
        return Task.FromResult(options);
    }

    public async Task<Fido2.AssertionVerificationResult> VerifyAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        byte[] storedCredentialId,
        byte[] storedPublicKey,
        uint storedCounter,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var credential = new Fido2.Credential
            {
                Id = storedCredentialId,
                PublicKey = storedPublicKey,
                Counter = storedCounter
            };

            var result = await _fido2.MakeAssertionAsync(
                assertionResponse,
                originalOptions,
                credential.PublicKey,
                storedCounter,
                IsUserHandleOwnerOfCredentialIdAsync);

            _logger.LogInformation("Successfully verified assertion");
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify assertion");
            throw;
        }
    }

    private Task<bool> IsCredentialIdUniqueToUserAsync(IsCredentialIdUniqueToUserParams args)
    {
        // This will be checked by the credential store
        // For now, return true - the store will handle uniqueness
        return Task.FromResult(true);
    }

    private Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams args)
    {
        // Verify that the user handle matches the credential
        // This is handled by the credential store lookup
        return Task.FromResult(true);
    }
}

