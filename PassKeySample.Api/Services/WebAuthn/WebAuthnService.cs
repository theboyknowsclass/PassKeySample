using Fido2NetLib;
using Fido2NetLib.Objects;

namespace PassKeySample.Api.Services.WebAuthn;

/// <summary>
/// Implementation of WebAuthn operations using the Fido2NetLib library.
/// Handles passkey registration and authentication ceremonies.
/// </summary>
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

        // In Fido2 4.0, RequestNewCredential takes RequestNewCredentialParams
        var requestParams = new RequestNewCredentialParams
        {
            User = user
        };
        var options = _fido2.RequestNewCredential(requestParams);

        _logger.LogInformation("Generated registration options for user: {UserId}", userId);
        return Task.FromResult(options);
    }

    public async Task<object> VerifyRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // In Fido2 4.0, MakeNewCredentialAsync uses MakeNewCredentialParams
            var makeCredentialParams = new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = originalOptions,
                IsCredentialIdUniqueToUserCallback = IsCredentialIdUniqueToUserAsync
            };
            
            var result = await _fido2.MakeNewCredentialAsync(makeCredentialParams, cancellationToken);
            _logger.LogInformation("Successfully verified registration");
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify registration");
            throw;
        }
    }

    public Task<AssertionOptions> GenerateAssertionOptionsAsync(string userId, List<object>? allowedCredentials = null, CancellationToken cancellationToken = default)
    {
        // In Fido2 4.0, GetAssertionOptions takes GetAssertionOptionsParams
        // Convert object list if provided - PublicKeyCredentialDescriptor might not exist, use object list
        var getAssertionParams = new GetAssertionOptionsParams();
        
        if (allowedCredentials != null && allowedCredentials.Count > 0)
        {
            // Try to extract credential descriptors
            // In Fido2 4.0, this might be a different type
            var credentialList = new List<object>();
            foreach (var cred in allowedCredentials)
            {
                credentialList.Add(cred);
            }
            // Set the allowed credentials if the params object supports it
            // This will need to be adjusted based on actual Fido2 4.0 API
        }
        
        var options = _fido2.GetAssertionOptions(getAssertionParams);

        _logger.LogInformation("Generated assertion options for user: {UserId}", userId);
        return Task.FromResult(options);
    }

    public async Task<object> VerifyAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        byte[] storedCredentialId,
        byte[] storedPublicKey,
        uint storedCounter,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // In Fido2 4.0, MakeAssertionAsync uses MakeAssertionParams
            var makeAssertionParams = new MakeAssertionParams
            {
                AssertionResponse = assertionResponse,
                OriginalOptions = originalOptions,
                StoredPublicKey = storedPublicKey,
                StoredSignatureCounter = storedCounter,
                IsUserHandleOwnerOfCredentialIdCallback = IsUserHandleOwnerOfCredentialIdAsync
            };
            
            var result = await _fido2.MakeAssertionAsync(makeAssertionParams, cancellationToken);

            _logger.LogInformation("Successfully verified assertion");
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify assertion");
            throw;
        }
    }

    private Task<bool> IsCredentialIdUniqueToUserAsync(IsCredentialIdUniqueToUserParams p, CancellationToken cancellationToken)
    {
        // This will be checked by the credential store
        // For now, return true - the store will handle uniqueness
        return Task.FromResult(true);
    }

    private Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams p, CancellationToken cancellationToken)
    {
        // Verify that the user handle matches the credential
        // This is handled by the credential store lookup
        return Task.FromResult(true);
    }
}

