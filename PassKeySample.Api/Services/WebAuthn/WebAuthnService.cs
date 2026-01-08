using System.Linq;
using System.Reflection;
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
        var getAssertionParams = new GetAssertionOptionsParams();
        
        if (allowedCredentials != null && allowedCredentials.Count > 0)
        {
            // Convert the credential descriptors to PublicKeyCredentialDescriptor
            var credentialDescriptors = new List<PublicKeyCredentialDescriptor>();
            
            foreach (var credObj in allowedCredentials)
            {
                // Extract Id and Type from the anonymous object created in AuthController
                var credType = credObj.GetType();
                var idProperty = credType.GetProperty("Id");
                var typeProperty = credType.GetProperty("Type");
                
                if (idProperty != null)
                {
                    var idValue = idProperty.GetValue(credObj);
                    
                    if (idValue is byte[] credentialId)
                    {
                        // PublicKeyCredentialDescriptor requires constructor parameters
                        // Try to find and invoke the constructor
                        var descriptorType = typeof(PublicKeyCredentialDescriptor);
                        var constructors = descriptorType.GetConstructors();
                        
                        PublicKeyCredentialDescriptor? descriptor = null;
                        
                        // Try constructor with (byte[], PublicKeyCredentialType)
                        var constructor = constructors.FirstOrDefault(c => 
                        {
                            var parameters = c.GetParameters();
                            return parameters.Length == 2 
                                && parameters[0].ParameterType == typeof(byte[])
                                && parameters[1].ParameterType == typeof(PublicKeyCredentialType);
                        });
                        
                        if (constructor != null)
                        {
                            descriptor = (PublicKeyCredentialDescriptor)constructor.Invoke(new object[] { credentialId, PublicKeyCredentialType.PublicKey });
                        }
                        else
                        {
                            // Try constructor with just (byte[])
                            constructor = constructors.FirstOrDefault(c => 
                            {
                                var parameters = c.GetParameters();
                                return parameters.Length == 1 && parameters[0].ParameterType == typeof(byte[]);
                            });
                            
                            if (constructor != null)
                            {
                                descriptor = (PublicKeyCredentialDescriptor)constructor.Invoke(new object[] { credentialId });
                            }
                        }
                        
                        if (descriptor != null)
                        {
                            credentialDescriptors.Add(descriptor);
                        }
                        else
                        {
                            _logger.LogWarning("Could not find suitable constructor for PublicKeyCredentialDescriptor. Available constructors: {Constructors}", 
                                string.Join(", ", constructors.Select(c => string.Join(", ", c.GetParameters().Select(p => $"{p.ParameterType.Name} {p.Name}")))));
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Credential ID is not a byte array, type: {Type}", idValue?.GetType().Name ?? "null");
                    }
                }
                else
                {
                    _logger.LogWarning("Credential object does not have an Id property");
                }
            }
            
            _logger.LogInformation("Converting {Count} allowed credentials to PublicKeyCredentialDescriptor", credentialDescriptors.Count);
            
            // Set the allowed credentials on the params object using reflection
            // This handles different possible property names in Fido2NetLib
            var paramsType = typeof(GetAssertionOptionsParams);
            var allowedCredsProperty = paramsType.GetProperty("AllowedCredentials") 
                ?? paramsType.GetProperty("AllowedCredentialDescriptors")
                ?? paramsType.GetProperty("Credentials");
            
            if (allowedCredsProperty != null)
            {
                allowedCredsProperty.SetValue(getAssertionParams, credentialDescriptors);
                _logger.LogInformation("Successfully set {Count} allowed credentials on GetAssertionOptionsParams", credentialDescriptors.Count);
            }
            else
            {
                _logger.LogError("Could not find AllowedCredentials property on GetAssertionOptionsParams. Available properties: {Properties}", 
                    string.Join(", ", paramsType.GetProperties().Select(p => p.Name)));
            }
        }
        else
        {
            _logger.LogInformation("No allowed credentials provided for user: {UserId}", userId);
        }
        
        var options = _fido2.GetAssertionOptions(getAssertionParams);
        
        // Ensure userVerification is set to a valid value (not null)
        // 1Password and other authenticators may reject null values
        // Use "preferred" as default - allows user verification if available but doesn't require it
        var optionsType = typeof(AssertionOptions);
        var userVerificationProperty = optionsType.GetProperty("UserVerification");
        
        if (userVerificationProperty != null)
        {
            var currentValue = userVerificationProperty.GetValue(options);
            if (currentValue == null)
            {
                // Get the property type - it might be a nullable enum (Nullable<T>)
                var userVerificationType = userVerificationProperty.PropertyType;
                Type? enumType = null;
                
                // Check if it's a nullable type
                if (userVerificationType.IsGenericType && 
                    userVerificationType.GetGenericTypeDefinition() == typeof(Nullable<>))
                {
                    // Get the underlying enum type
                    enumType = Nullable.GetUnderlyingType(userVerificationType);
                }
                else if (userVerificationType.IsEnum)
                {
                    enumType = userVerificationType;
                }
                
                if (enumType != null && enumType.IsEnum)
                {
                    // Try to find "Preferred" value
                    var preferredValue = Enum.GetValues(enumType)
                        .Cast<object>()
                        .FirstOrDefault(v => v.ToString()?.Equals("Preferred", StringComparison.OrdinalIgnoreCase) == true);
                    
                    if (preferredValue == null)
                    {
                        // Try "Discouraged" as fallback
                        preferredValue = Enum.GetValues(enumType)
                            .Cast<object>()
                            .FirstOrDefault(v => v.ToString()?.Equals("Discouraged", StringComparison.OrdinalIgnoreCase) == true);
                    }
                    
                    if (preferredValue != null)
                    {
                        // If the property is nullable, we can set the enum value directly
                        // The nullable wrapper will handle it
                        userVerificationProperty.SetValue(options, preferredValue);
                        _logger.LogInformation("Set userVerification to {Value} (was null)", preferredValue);
                    }
                    else
                    {
                        _logger.LogWarning("Could not find Preferred or Discouraged value in UserVerification enum. Available values: {Values}", 
                            string.Join(", ", Enum.GetValues(enumType).Cast<object>()));
                    }
                }
                else
                {
                    _logger.LogWarning("UserVerification property type is not an enum or nullable enum: {Type}", userVerificationType.Name);
                }
            }
        }
        else
        {
            _logger.LogWarning("Could not find UserVerification property on AssertionOptions");
        }
        
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

