using System.Text;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using PassKeySample.Api.Models;
using PassKeySample.Api.Services;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IWebAuthnService _webauthnService;
    private readonly IWebAuthnCredentialStore _credentialStore;
    private readonly IIdpUserService _idpUserService;
    private readonly IdentityProviderOptions _idpOptions;
    private readonly HttpClient _httpClient;
    private readonly ILogger<AuthController> _logger;
    private readonly IMemoryCache _challengeCache;

    public AuthController(
        IWebAuthnService webauthnService,
        IWebAuthnCredentialStore credentialStore,
        IIdpUserService idpUserService,
        IdentityProviderOptions idpOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<AuthController> logger,
        IMemoryCache challengeCache)
    {
        _webauthnService = webauthnService;
        _credentialStore = credentialStore;
        _idpUserService = idpUserService;
        _idpOptions = idpOptions;
        _httpClient = httpClientFactory.CreateClient();
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
            // Always check if user exists, but don't reveal the result
            var userExists = await _idpUserService.UserExistsAsync(request.UsernameOrEmail, cancellationToken);
            var userId = await _idpUserService.GetUserIdAsync(request.UsernameOrEmail, cancellationToken);
            
            List<PublicKeyCredentialDescriptor> credentialDescriptors = new();
            
            // Only get credentials if user exists and has a valid user ID
            if (userExists && userId != null)
            {
                var existingCredentials = await _credentialStore.GetCredentialsAsync(userId, cancellationToken);
                credentialDescriptors = existingCredentials
                    .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
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

            // Get user's credentials
            var credentials = await _credentialStore.GetCredentialsAsync(challengeData.UserId, cancellationToken);
            if (credentials.Count == 0)
            {
                // No credentials - return generic error
                _logger.LogWarning("No credentials found for user: {UserId}", challengeData.UserId);
                return BadRequest(new { Error = "Authentication failed" });
            }

            // Find the credential being used
            var credentialId = Convert.FromBase64String(request.Response.Id);
            var credential = credentials.FirstOrDefault(c => c.CredentialId.SequenceEqual(credentialId));
            if (credential == null)
            {
                // Credential not found - return generic error
                _logger.LogWarning("Credential not found for user: {UserId}", challengeData.UserId);
                return BadRequest(new { Error = "Authentication failed" });
            }

            // Use stored assertion options
            var assertionOptions = challengeData.AssertionOptions;
            if (assertionOptions == null)
            {
                return BadRequest(new { Error = "Invalid challenge data" });
            }

            // Verify the assertion
            var assertionResponse = new AuthenticatorAssertionRawResponse
            {
                Id = request.Response.Id,
                RawId = request.Response.RawId,
                Response = new AuthenticatorAssertionRawResponse.ResponseData
                {
                    ClientDataJson = request.Response.Response.ClientDataJson,
                    AuthenticatorData = request.Response.Response.AuthenticatorData,
                    Signature = request.Response.Response.Signature,
                    UserHandle = request.Response.Response.UserHandle
                },
                Type = PublicKeyCredentialType.PublicKey
            };

            var verificationResult = await _webauthnService.VerifyAssertionAsync(
                assertionResponse,
                assertionOptions,
                credential.CredentialId,
                credential.PublicKey,
                credential.Counter,
                cancellationToken);

            if (!verificationResult.Status.Equals("Ok", StringComparison.OrdinalIgnoreCase))
            {
                // Return generic error without revealing specific failure reason
                _logger.LogWarning("WebAuthn verification failed for user: {UserId}, Status: {Status}", challengeData.UserId, verificationResult.Status);
                return BadRequest(new { Error = "Authentication failed" });
            }

            // Update credential counter
            await _credentialStore.UpdateCounterAsync(
                challengeData.UserId,
                credential.CredentialId,
                verificationResult.Counter,
                cancellationToken);

            // Get OAuth token from IDP (user-specific with refresh token)
            var tokenResponse = await GetOAuthTokenAsync(challengeData.UsernameOrEmail, challengeData.UserId, cancellationToken);
            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
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

    private async Task<OAuthTokenResponse?> GetOAuthTokenAsync(string usernameOrEmail, string userId, CancellationToken cancellationToken)
    {
        try
        {
            // Get token endpoint from discovery or construct it
            var discovery = await HttpContext.RequestServices.GetRequiredService<OidcDiscoveryService>().GetDiscoveryDocumentAsync(cancellationToken);
            var tokenEndpoint = discovery?.TokenEndpoint ?? $"{_idpOptions.GetBaseUrl()}/realms/passkeysample/protocol/openid-connect/token";
            
            // Use Resource Owner Password Credentials grant to get user-specific tokens
            // Note: Since we've verified the user via WebAuthn, we can request tokens for that user
            // In production, you might use a custom grant type or token exchange
            // For Keycloak, we'll use the direct access grant with the username
            var requestData = new Dictionary<string, string>
            {
                { "grant_type", "password" }, // Resource Owner Password Credentials
                { "client_id", _idpOptions.ClientId },
                { "client_secret", _idpOptions.ClientSecret },
                { "username", usernameOrEmail },
                { "password", "webauthn-verified" }, // Placeholder - WebAuthn verification serves as password proof
                { "scope", "openid profile email offline_access" } // offline_access for refresh token
            };

            var content = new FormUrlEncodedContent(requestData);
            var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                // If password grant fails (expected if IDP doesn't accept placeholder password),
                // fall back to client credentials for now
                // In production, implement proper token exchange or custom grant
                _logger.LogWarning("Password grant failed, attempting client credentials fallback. Status: {Status}, Response: {Response}",
                    response.StatusCode, await response.Content.ReadAsStringAsync(cancellationToken));
                
                // Fallback to client credentials (non-user-specific)
                requestData = new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", _idpOptions.ClientId },
                    { "client_secret", _idpOptions.ClientSecret },
                    { "scope", "openid profile email" }
                };

                content = new FormUrlEncodedContent(requestData);
                response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Failed to get OAuth token. Status: {Status}, Response: {Response}",
                        response.StatusCode, await response.Content.ReadAsStringAsync(cancellationToken));
                    return null;
                }
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<OAuthTokenResponse>(cancellationToken: cancellationToken);
            return tokenResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting OAuth token");
            return null;
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
            var attestationResponse = new AuthenticatorAttestationRawResponse
            {
                Id = request.Response.Id,
                RawId = request.Response.RawId,
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    ClientDataJson = request.Response.Response.ClientDataJson,
                    AttestationObject = request.Response.Response.AttestationObject
                },
                Type = PublicKeyCredentialType.PublicKey
            };

            // Get registration options from challenge data (would need to store these)
            // For now, we'll need to reconstruct or store them
            // This is a simplified version - in production, store the full options
            var registrationOptions = challengeData.RegistrationOptions;
            if (registrationOptions == null)
            {
                return BadRequest(new { Error = "Invalid challenge data for registration" });
            }

            var verificationResult = await _webauthnService.VerifyRegistrationAsync(
                attestationResponse,
                registrationOptions,
                cancellationToken);

            if (!verificationResult.Status.Equals("Ok", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest(new { Error = "WebAuthn registration failed", Status = verificationResult.Status });
            }

            // Store the credential
            var credential = new WebAuthnCredential
            {
                UserId = userId,
                CredentialId = verificationResult.CredentialId,
                PublicKey = verificationResult.PublicKey,
                Counter = 0,
                CreatedAt = DateTime.UtcNow
            };

            await _credentialStore.StoreCredentialAsync(credential, cancellationToken);

            _logger.LogInformation("WebAuthn registration successful for user: {UserId}", userId);

            return Ok(new { Message = "Credential registered successfully" });
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

public class RefreshTokenRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}

public class OAuthTokenResponse
{
    public string? AccessToken { get; set; }
    public string? TokenType { get; set; }
    public int? ExpiresIn { get; set; }
    public string? RefreshToken { get; set; }
}

