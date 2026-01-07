using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using PassKeySample.Api.Configuration;
using PassKeySample.Api.Models;
using PassKeySample.Api.Services.Identity;
using PassKeySample.Api.Services.WebAuthn;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IWebAuthnService _webauthnService;
    private readonly IWebAuthnCredentialStore _credentialStore;
    private readonly IIdpUserService _idpUserService;
    private readonly ITokenExchangeService _tokenExchangeService;
    private readonly ILogger<AuthController> _logger;
    private readonly IMemoryCache _challengeCache;

    public AuthController(
        IWebAuthnService webauthnService,
        IWebAuthnCredentialStore credentialStore,
        IIdpUserService idpUserService,
        ITokenExchangeService tokenExchangeService,
        ILogger<AuthController> logger,
        IMemoryCache challengeCache)
    {
        _webauthnService = webauthnService;
        _credentialStore = credentialStore;
        _idpUserService = idpUserService;
        _tokenExchangeService = tokenExchangeService;
        _logger = logger;
        _challengeCache = challengeCache;
    }

    [HttpPost("webauthn/options")]
    public async Task<IActionResult> GetWebAuthnOptions([FromBody] WebAuthnOptionsRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.UsernameOrEmail))
        {
            return BadRequest(new { Error = "Username or email is required" });
        }

        try
        {
            // TODO: REMOVE - DEBUG CODE ONLY
            // Log all users in credential store for debugging
            if (_credentialStore is InMemoryWebAuthnCredentialStore inMemoryStore)
            {
                var allUsers = inMemoryStore.GetAllUsersDebug();
                _logger.LogInformation("DEBUG: All users in credential store: {UserCount} users", allUsers.Count);
                foreach (var user in allUsers)
                {
                    _logger.LogInformation("DEBUG: User {UserId} has {CredentialCount} credential(s)", 
                        user.Key, user.Value.Count);
                }
            }

            // Always check if user exists, but don't reveal the result
            var userExists = await _idpUserService.UserExistsAsync(request.UsernameOrEmail, cancellationToken);
            var userId = await _idpUserService.GetUserIdAsync(request.UsernameOrEmail, cancellationToken);
            
            List<object> credentialDescriptors = new();
            
            // Only get credentials if user exists and has a valid user ID
            if (userExists && userId != null)
            {
                var existingCredentials = await _credentialStore.GetCredentialsAsync(userId, cancellationToken);
                // Convert to PublicKeyCredentialDescriptor for Fido2
                // Create credential descriptors - in Fido2 4.0, type might be different
                // For now, create objects that will be converted in the service
                credentialDescriptors = existingCredentials
                    .Select(c => (object)new { Id = c.CredentialId, Type = "public-key" })
                    .ToList();
            }
            else
            {
                // User doesn't exist - use a dummy user ID for options generation
                // This will ensure verification always fails without revealing user existence
                userId = $"dummy_{Guid.NewGuid()}";
                _logger.LogInformation("User not found for: {UsernameOrEmail}, returning options that will fail verification", request.UsernameOrEmail);
            }

            // Generate assertion options with allowed credentials (empty list if user doesn't exist)
            var options = await _webauthnService.GenerateAssertionOptionsAsync(userId, credentialDescriptors, cancellationToken);

            // Store challenge and options in cache (expires in 5 minutes)
            var challengeKey = $"webauthn_challenge_{userId}_{Guid.NewGuid()}";
            _challengeCache.Set(challengeKey, new ChallengeData
            {
                Challenge = options.Challenge,
                AssertionOptions = options,
                UserId = userId,
                UsernameOrEmail = request.UsernameOrEmail,
                UserExists = userExists && userId != null && !userId.StartsWith("dummy_")
            }, TimeSpan.FromMinutes(5));

            _logger.LogInformation("Generated WebAuthn options for: {UsernameOrEmail}", request.UsernameOrEmail);

            return Ok(new
            {
                Options = options,
                ChallengeKey = challengeKey
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate WebAuthn options");
            return StatusCode(500, new { Error = "Failed to generate WebAuthn options", Message = ex.Message });
        }
    }

    [HttpPost("webauthn/verify")]
    public async Task<IActionResult> VerifyWebAuthn([FromBody] WebAuthnVerifyRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.ChallengeKey))
        {
            return BadRequest(new { Error = "Challenge key is required" });
        }

        if (request.Response == null)
        {
            return BadRequest(new { Error = "WebAuthn response is required" });
        }

        try
        {
            // TODO: REMOVE - DEBUG CODE ONLY
            // Log all users in credential store for debugging
            if (_credentialStore is InMemoryWebAuthnCredentialStore inMemoryStore)
            {
                var allUsers = inMemoryStore.GetAllUsersDebug();
                _logger.LogInformation("DEBUG: All users in credential store: {UserCount} users", allUsers.Count);
                foreach (var user in allUsers)
                {
                    _logger.LogInformation("DEBUG: User {UserId} has {CredentialCount} credential(s)", 
                        user.Key, user.Value.Count);
                }
            }

            // Retrieve challenge from cache
            if (!_challengeCache.TryGetValue<ChallengeData>(request.ChallengeKey, out var challengeData) || challengeData == null)
            {
                return BadRequest(new { Error = "Invalid or expired challenge" });
            }

            // Remove challenge from cache (one-time use)
            _challengeCache.Remove(request.ChallengeKey);

            // Check if user exists (without revealing it)
            if (!challengeData.UserExists)
            {
                // User doesn't exist - return generic error without revealing user existence
                _logger.LogWarning("Authentication attempt for non-existent user: {UsernameOrEmail}", challengeData.UsernameOrEmail);
                return BadRequest(new { Error = "Authentication failed" });
            }

            // Verify the assertion
            // Convert base64url strings to byte arrays
            static byte[] Base64UrlDecode(string base64Url)
            {
                var base64 = base64Url.Replace('-', '+').Replace('_', '/');
                switch (base64.Length % 4)
                {
                    case 2: base64 += "=="; break;
                    case 3: base64 += "="; break;
                }
                return Convert.FromBase64String(base64);
            }

            // Find the credential being used
            // The credential ID from frontend is base64url encoded, not regular base64
            var credentialId = Base64UrlDecode(request.Response.Id);
            
            // Look up credential from server store (proper WebAuthn implementation)
            var credentials = await _credentialStore.GetCredentialsAsync(challengeData.UserId, cancellationToken);
            var credential = credentials.FirstOrDefault(c => c.CredentialId.SequenceEqual(credentialId));
            
            if (credential == null)
            {
                _logger.LogWarning("Credential not found for user: {UserId}, credentialId length: {CredentialIdLength}", 
                    challengeData.UserId, credentialId.Length);
                return BadRequest(new { Error = "Authentication failed" });
            }
            
            _logger.LogInformation("Found credential in store for user: {UserId}", challengeData.UserId);

            // Use stored assertion options
            var assertionOptions = challengeData.AssertionOptions;
            if (assertionOptions == null)
            {
                return BadRequest(new { Error = "Invalid challenge data" });
            }

            var rawIdBytes = Base64UrlDecode(request.Response.RawId);
            var clientDataJsonBytes = Base64UrlDecode(request.Response.Response.ClientDataJson);
            var authenticatorDataBytes = Base64UrlDecode(request.Response.Response.AuthenticatorData);
            var signatureBytes = Base64UrlDecode(request.Response.Response.Signature);
            byte[]? userHandleBytes = null;
            if (!string.IsNullOrEmpty(request.Response.Response.UserHandle))
            {
                userHandleBytes = Base64UrlDecode(request.Response.Response.UserHandle);
            }

            // In Fido2 4.0, AuthenticatorAssertionRawResponse structure
            // Create using object initializer with all properties
            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Id = request.Response.Id,
                RawId = rawIdBytes,
                Type = PublicKeyCredentialType.PublicKey
            };
            
            // Set Response property - it's an init-only property, so use reflection
            var responseType = typeof(AuthenticatorAssertionRawResponse);
            var responseProp = responseType.GetProperty("Response");
            if (responseProp != null)
            {
                var responseDataObj = Activator.CreateInstance(responseProp.PropertyType);
                var dataType = responseProp.PropertyType;
                dataType.GetProperty("ClientDataJson")?.SetValue(responseDataObj, clientDataJsonBytes);
                dataType.GetProperty("AuthenticatorData")?.SetValue(responseDataObj, authenticatorDataBytes);
                dataType.GetProperty("Signature")?.SetValue(responseDataObj, signatureBytes);
                dataType.GetProperty("UserHandle")?.SetValue(responseDataObj, userHandleBytes);
                
                // Set init-only property via backing field
                var backingField = responseType.GetField("<Response>k__BackingField", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                backingField?.SetValue(assertionResponse, responseDataObj);
            }

            // In Fido2 4.0, if MakeAssertionAsync succeeds, it returns a result object
            // If it fails, it throws an exception, so no need to check Status
            var verificationResult = await _webauthnService.VerifyAssertionAsync(
                assertionResponse,
                assertionOptions,
                credential.CredentialId,
                credential.PublicKey,
                credential.Counter,
                cancellationToken);

            // Access Counter property using reflection (Fido2 4.0 VerifyAssertionResult type)
            var resultType = verificationResult.GetType();
            var counterProperty = resultType.GetProperty("Counter") 
                ?? resultType.GetProperty("SignatureCounter")
                ?? resultType.GetProperty("CounterValue");
            
            uint counter = 0u;
            if (counterProperty != null)
            {
                var counterValue = counterProperty.GetValue(verificationResult);
                if (counterValue != null)
                {
                    counter = Convert.ToUInt32(counterValue);
                }
            }
            else
            {
                _logger.LogWarning("Could not find Counter property on verification result type: {Type}", resultType.FullName);
                // Log available properties for debugging
                var properties = resultType.GetProperties().Select(p => p.Name).ToList();
                _logger.LogInformation("Available properties: {Properties}", string.Join(", ", properties));
            }
            await _credentialStore.UpdateCounterAsync(
                challengeData.UserId,
                credential.CredentialId,
                counter,
                cancellationToken);

            // Get OAuth token from IDP using Token Exchange (RFC 8693)
            var tokenResponse = await _tokenExchangeService.ExchangeForUserTokenAsync(challengeData.UsernameOrEmail, challengeData.UserId, cancellationToken);
            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                _logger.LogError("Failed to obtain OAuth token from IDP via Token Exchange for user: {UserId}", challengeData.UserId);
                return StatusCode(500, new { Error = "Failed to obtain OAuth token from IDP" });
            }

            _logger.LogInformation("WebAuthn verification successful for user: {UserId}", challengeData.UserId);

            return Ok(new
            {
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = tokenResponse.RefreshToken,
                ExpiresIn = tokenResponse.ExpiresIn ?? 3600,
                TokenType = "DPoP"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify WebAuthn");
            return StatusCode(500, new { Error = "Failed to verify WebAuthn", Message = ex.Message });
        }
    }


    [HttpPost("webauthn/register/options")]
    public async Task<IActionResult> GetRegistrationOptions([FromBody] WebAuthnOptionsRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.UsernameOrEmail))
        {
            return BadRequest(new { Error = "Username or email is required" });
        }

        try
        {
            // Check if user exists in IDP
            var userExists = await _idpUserService.UserExistsAsync(request.UsernameOrEmail, cancellationToken);
            if (!userExists)
            {
                return NotFound(new { Error = "User not found" });
            }

            var userId = await _idpUserService.GetUserIdAsync(request.UsernameOrEmail, cancellationToken);
            if (userId == null)
            {
                return NotFound(new { Error = "Unable to determine user ID" });
            }

            // Generate registration options
            var options = await _webauthnService.GenerateRegistrationOptionsAsync(userId, request.UsernameOrEmail, cancellationToken);

            // Store challenge and options in cache (expires in 5 minutes)
            var challengeKey = $"webauthn_reg_challenge_{userId}_{Guid.NewGuid()}";
            _challengeCache.Set(challengeKey, new ChallengeData
            {
                Challenge = options.Challenge,
                RegistrationOptions = options,
                UserId = userId,
                UsernameOrEmail = request.UsernameOrEmail
            }, TimeSpan.FromMinutes(5));

            _logger.LogInformation("Generated WebAuthn registration options for user: {UserId}", userId);

            return Ok(new
            {
                Options = options,
                ChallengeKey = challengeKey
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate WebAuthn registration options");
            return StatusCode(500, new { Error = "Failed to generate WebAuthn registration options", Message = ex.Message });
        }
    }

    [HttpPost("webauthn/register")]
    public async Task<IActionResult> RegisterWebAuthn([FromBody] WebAuthnRegisterRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.UsernameOrEmail))
        {
            return BadRequest(new { Error = "Username or email is required" });
        }

        if (request.Response == null)
        {
            return BadRequest(new { Error = "WebAuthn response is required" });
        }

        try
        {
            // Check if user exists in IDP
            var userExists = await _idpUserService.UserExistsAsync(request.UsernameOrEmail, cancellationToken);
            if (!userExists)
            {
                return NotFound(new { Error = "User not found" });
            }

            var userId = await _idpUserService.GetUserIdAsync(request.UsernameOrEmail, cancellationToken);
            if (userId == null)
            {
                return NotFound(new { Error = "Unable to determine user ID" });
            }

            // Retrieve challenge from cache
            if (!_challengeCache.TryGetValue<ChallengeData>(request.ChallengeKey, out var challengeData) || challengeData == null)
            {
                return BadRequest(new { Error = "Invalid or expired challenge" });
            }

            // Remove challenge from cache (one-time use)
            _challengeCache.Remove(request.ChallengeKey);

            // Verify the registration
            // Convert base64url strings to byte arrays
            static byte[] Base64UrlDecode(string base64Url)
            {
                var base64 = base64Url.Replace('-', '+').Replace('_', '/');
                switch (base64.Length % 4)
                {
                    case 2: base64 += "=="; break;
                    case 3: base64 += "="; break;
                }
                return Convert.FromBase64String(base64);
            }

            var rawIdBytes = Base64UrlDecode(request.Response.RawId);
            var clientDataJsonBytes = Base64UrlDecode(request.Response.Response.ClientDataJson);
            var attestationObjectBytes = Base64UrlDecode(request.Response.Response.AttestationObject);

            // In Fido2 4.0, AuthenticatorAttestationRawResponse structure
            var attestationResponse = new AuthenticatorAttestationRawResponse
            {
                Id = request.Response.Id,
                RawId = rawIdBytes,
                Type = PublicKeyCredentialType.PublicKey
            };
            
            // Set Response property using reflection
            var attestationResponseType = typeof(AuthenticatorAttestationRawResponse);
            var responseProp = attestationResponseType.GetProperty("Response");
            if (responseProp != null)
            {
                var responseDataObj = Activator.CreateInstance(responseProp.PropertyType);
                var dataType = responseProp.PropertyType;
                dataType.GetProperty("ClientDataJson")?.SetValue(responseDataObj, clientDataJsonBytes);
                dataType.GetProperty("AttestationObject")?.SetValue(responseDataObj, attestationObjectBytes);
                
                var backingField = attestationResponseType.GetField("<Response>k__BackingField", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                backingField?.SetValue(attestationResponse, responseDataObj);
            }

            // Get registration options from challenge data (would need to store these)
            // For now, we'll need to reconstruct or store them
            // This is a simplified version - in production, store the full options
            var registrationOptions = challengeData.RegistrationOptions;
            if (registrationOptions == null)
            {
                return BadRequest(new { Error = "Invalid challenge data for registration" });
            }

            // In Fido2 4.0, if MakeNewCredentialAsync succeeds, it returns RegisteredPublicKeyCredential
            // If it fails, it throws an exception, so no need to check Status
            var verificationResult = await _webauthnService.VerifyRegistrationAsync(
                attestationResponse,
                registrationOptions,
                cancellationToken);

            // Access properties using reflection (Fido2 4.0 RegisteredPublicKeyCredential type)
            var resultType = verificationResult.GetType();
            var idProperty = resultType.GetProperty("Id") ?? resultType.GetProperty("CredentialId");
            var publicKeyProperty = resultType.GetProperty("PublicKey");
            
            byte[] credentialId = idProperty?.GetValue(verificationResult) as byte[] ?? Array.Empty<byte>();
            byte[] publicKey = publicKeyProperty?.GetValue(verificationResult) as byte[] ?? Array.Empty<byte>();
            
            if (credentialId.Length == 0 || publicKey.Length == 0)
            {
                _logger.LogError("Failed to extract credential ID or public key from verification result. Type: {Type}", resultType.FullName);
                return BadRequest(new { Error = "Failed to extract credential information from verification result" });
            }
            
            var credential = new WebAuthnCredential
            {
                UserId = userId,
                CredentialId = credentialId,
                PublicKey = publicKey,
                Counter = 0,
                CreatedAt = DateTime.UtcNow
            };

            // Store credential on server (proper WebAuthn implementation)
            await _credentialStore.StoreCredentialAsync(credential, cancellationToken);
            
            _logger.LogInformation("WebAuthn registration successful for user: {UserId}, CredentialId length: {CredentialIdLength}, PublicKey length: {PublicKeyLength}. Credential stored on server.", 
                userId, credential.CredentialId.Length, credential.PublicKey.Length);

            return Ok(new 
            { 
                Message = "Credential registered successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register WebAuthn credential");
            return StatusCode(500, new { Error = "Failed to register WebAuthn credential", Message = ex.Message });
        }
    }
}

// Request/Response models
public class WebAuthnOptionsRequest
{
    public string UsernameOrEmail { get; set; } = string.Empty;
}

public class WebAuthnVerifyRequest
{
    public string ChallengeKey { get; set; } = string.Empty;
    public WebAuthnResponse? Response { get; set; }
    // PublicKey removed - server now looks up credential by credential ID from the WebAuthn response
}

public class WebAuthnRegisterRequest
{
    public string UsernameOrEmail { get; set; } = string.Empty;
    public string ChallengeKey { get; set; } = string.Empty;
    public WebAuthnRegistrationResponse? Response { get; set; }
}

public class WebAuthnRegistrationResponse
{
    public string Id { get; set; } = string.Empty;
    public string RawId { get; set; } = string.Empty;
    public WebAuthnRegistrationResponseData Response { get; set; } = new();
    public string Type { get; set; } = "public-key";
}

public class WebAuthnRegistrationResponseData
{
    public string ClientDataJson { get; set; } = string.Empty;
    public string AttestationObject { get; set; } = string.Empty;
}

public class WebAuthnResponse
{
    public string Id { get; set; } = string.Empty;
    public string RawId { get; set; } = string.Empty;
    public WebAuthnResponseData Response { get; set; } = new();
    public string Type { get; set; } = "public-key";
}

public class WebAuthnResponseData
{
    public string ClientDataJson { get; set; } = string.Empty;
    public string AuthenticatorData { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public string? UserHandle { get; set; }
}

public class ChallengeData
{
    public byte[] Challenge { get; set; } = Array.Empty<byte>();
    public AssertionOptions? AssertionOptions { get; set; }
    public CredentialCreateOptions? RegistrationOptions { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string UsernameOrEmail { get; set; } = string.Empty;
    public bool UserExists { get; set; } = true;
}

public class RefreshTokenRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}

