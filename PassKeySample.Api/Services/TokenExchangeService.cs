using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PassKeySample.Api.Configuration;

namespace PassKeySample.Api.Services;

public class TokenExchangeService : ITokenExchangeService
{
    private readonly OidcDiscoveryService _discoveryService;
    private readonly IdentityProviderOptions _idpOptions;
    private readonly HttpClient _httpClient;
    private readonly ILogger<TokenExchangeService> _logger;

    public TokenExchangeService(
        OidcDiscoveryService discoveryService,
        IdentityProviderOptions idpOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<TokenExchangeService> logger)
    {
        _discoveryService = discoveryService;
        _idpOptions = idpOptions;
        _httpClient = httpClientFactory.CreateClient("IdpClient");
        _logger = logger;
    }

    public async Task<OAuthTokenResponse?> ExchangeForUserTokenAsync(string usernameOrEmail, string userId, CancellationToken cancellationToken = default)
    {
        try
        {
            // Get token endpoint from discovery
            var discovery = await _discoveryService.GetDiscoveryDocumentAsync(cancellationToken);
            if (discovery == null || string.IsNullOrEmpty(discovery.TokenEndpoint))
            {
                _logger.LogError("OIDC discovery document is null or token endpoint is missing");
                return null;
            }

            var tokenEndpoint = discovery.TokenEndpoint;

            // Step 1: Get a service account token using client credentials
            var serviceTokenResponse = await GetServiceAccountTokenAsync(tokenEndpoint, cancellationToken);
            if (serviceTokenResponse == null || string.IsNullOrEmpty(serviceTokenResponse.AccessToken))
            {
                _logger.LogError("Failed to obtain service account token");
                return null;
            }

            // Step 2: Exchange service token for user token using RFC 8693 Token Exchange
            // IdP-agnostic approach: Try multiple strategies to get user token
            
            // Strategy 1: Try Token Exchange with requested_subject (RFC 8693 standard, optional parameter)
            // Some IdPs support this (e.g., ADFS, Azure AD), others don't (e.g., Keycloak < 26.2)
            var userSub = await TryGetUserIdFromUserInfoAsync(usernameOrEmail, serviceTokenResponse.AccessToken, discovery, cancellationToken);
            var requestedSubject = userSub ?? userId; // Use user ID if available, fallback to provided userId
            
            var exchangeRequest = new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                { "client_id", _idpOptions.ClientId },
                { "client_secret", _idpOptions.ClientSecret },
                { "subject_token", serviceTokenResponse.AccessToken }, // Service account token
                { "subject_token_type", "urn:ietf:params:oauth:token-type:access_token" },
                { "scope", $"openid profile email offline_access" } // Request user-specific scopes
            };

            // Add requested_subject if we have a user identifier (RFC 8693 optional parameter)
            // Note: Not all IdPs support this (Keycloak doesn't in standard token exchange)
            if (!string.IsNullOrEmpty(requestedSubject))
            {
                exchangeRequest["requested_subject"] = requestedSubject;
                _logger.LogInformation("Attempting Token Exchange with requested_subject: {RequestedSubject}", requestedSubject);
            }

            var content = new FormUrlEncodedContent(exchangeRequest);
            var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

            // Use case-insensitive JSON deserialization
            var jsonOptions = new System.Text.Json.JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            if (response.IsSuccessStatusCode)
            {
                var tokenResponse = await response.Content.ReadFromJsonAsync<OAuthTokenResponse>(jsonOptions, cancellationToken: cancellationToken);
                
                if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.AccessToken))
                {
                    // Verify the returned token is for the correct user by checking the 'sub' claim
                    var tokenSub = await GetTokenSubjectAsync(tokenResponse.AccessToken, cancellationToken);
                    
                    if (!string.IsNullOrEmpty(requestedSubject) && !string.IsNullOrEmpty(tokenSub))
                    {
                        if (tokenSub == requestedSubject)
                        {
                            _logger.LogInformation("Successfully exchanged service token for user token via Token Exchange (RFC 8693) for user: {UserId}", requestedSubject);
                            return tokenResponse;
                        }
                        else
                        {
                            _logger.LogWarning("Token Exchange succeeded but returned token for different user. Expected: {Expected}, Got: {Actual}", 
                                requestedSubject, tokenSub);
                            // Continue to check if it's still a valid user token (not service account)
                        }
                    }
                    
                    // If we got a token, verify it's a user token (not service account)
                    // Service account tokens typically have 'azp' or 'client_id' matching the client, 
                    // and may not have typical user claims like 'email' or 'preferred_username'
                    var handler = new JwtSecurityTokenHandler();
                    if (handler.CanReadToken(tokenResponse.AccessToken))
                    {
                        var jwt = handler.ReadJwtToken(tokenResponse.AccessToken);
                        var hasUserClaim = jwt.Claims.Any(c => c.Type == "email" || c.Type == "preferred_username");
                        var isServiceAccount = jwt.Claims.FirstOrDefault(c => c.Type == "azp" || c.Type == "client_id")?.Value == _idpOptions.ClientId;
                        
                        if (hasUserClaim && !isServiceAccount)
                        {
                            _logger.LogInformation("Successfully exchanged service token for user token via Token Exchange (RFC 8693). User: {TokenSub}", tokenSub);
                            return tokenResponse;
                        }
                        else if (isServiceAccount)
                        {
                            _logger.LogWarning("Token Exchange returned service account token instead of user token. This may require impersonation policies to be configured in the IdP.");
                        }
                    }
                    
                    // If we can't verify, still return it - let the caller validate
                    _logger.LogInformation("Token Exchange succeeded. Token subject: {TokenSub}", tokenSub ?? "unknown");
                    return tokenResponse;
                }
            }

            // Strategy 2: If requested_subject failed, try without it (for IdPs that don't support it)
            var errorResponse = await response.Content.ReadAsStringAsync(cancellationToken);
            var hasRequestedSubject = exchangeRequest.ContainsKey("requested_subject");
            
            if (hasRequestedSubject && errorResponse.Contains("requested_subject", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Token Exchange with requested_subject failed (not supported by this IdP). Trying without requested_subject. Error: {Error}", errorResponse);
                
                // Remove requested_subject and try again
                exchangeRequest.Remove("requested_subject");
                content = new FormUrlEncodedContent(exchangeRequest);
                response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);
                
                if (response.IsSuccessStatusCode)
                {
                    var tokenResponse = await response.Content.ReadFromJsonAsync<OAuthTokenResponse>(jsonOptions, cancellationToken: cancellationToken);
                    _logger.LogInformation("Token Exchange succeeded without requested_subject. Note: Returned token may be a service account token unless impersonation is configured.");
                    return tokenResponse;
                }
                
                errorResponse = await response.Content.ReadAsStringAsync(cancellationToken);
            }

            // Token Exchange failed - this is required, no fallback
            _logger.LogError("Token Exchange (RFC 8693) failed after all attempts. Status: {Status}, Response: {Response}. " +
                            "Token Exchange is required and must be properly configured in the IdP.",
                response.StatusCode, errorResponse);
            
            throw new InvalidOperationException(
                $"Token Exchange (RFC 8693) is required but failed. " +
                $"IdP returned: {response.StatusCode} - {errorResponse}. " +
                $"Please ensure: " +
                $"1. Token Exchange is enabled for client '{_idpOptions.ClientId}' in the IdP configuration, " +
                $"2. Service account has necessary permissions (may require impersonation roles/policies depending on IdP), " +
                $"3. For Keycloak: Enable 'Standard token exchange' capability and configure impersonation roles. " +
                $"4. For ADFS/Azure AD: Token Exchange with requested_subject may be supported - check IdP documentation.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token exchange");
            return null;
        }
    }

    private async Task<OAuthTokenResponse?> GetServiceAccountTokenAsync(string tokenEndpoint, CancellationToken cancellationToken)
    {
        try
        {
            var requestData = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", _idpOptions.ClientId },
                { "client_secret", _idpOptions.ClientSecret },
                { "scope", "openid profile email" }
            };

            var content = new FormUrlEncodedContent(requestData);
            var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get service account token. Status: {Status}, Response: {Response}",
                    response.StatusCode, await response.Content.ReadAsStringAsync(cancellationToken));
                return null;
            }

            // Use case-insensitive JSON deserialization to handle snake_case properties
            var options = new System.Text.Json.JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            
            var tokenResponse = await response.Content.ReadFromJsonAsync<OAuthTokenResponse>(options, cancellationToken);
            
            if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                _logger.LogInformation("Successfully obtained service account token");
            }
            
            return tokenResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting service account token");
            return null;
        }
    }

    /// <summary>
    /// Attempts to get user ID (sub claim) using OIDC UserInfo endpoint (standard OIDC).
    /// This is IdP-agnostic and works with any OIDC-compliant provider.
    /// </summary>
    private async Task<string?> TryGetUserIdFromUserInfoAsync(string usernameOrEmail, string serviceAccountToken, OidcDiscoveryDocument discovery, CancellationToken cancellationToken)
    {
        // UserInfo endpoint requires a user token, not a service account token.
        // However, some IdPs allow querying user info with service account tokens if proper permissions exist.
        // This is a best-effort attempt and may not work with all IdPs.
        
        if (string.IsNullOrEmpty(discovery.UserInfoEndpoint))
        {
            _logger.LogDebug("UserInfo endpoint not available in OIDC discovery document");
            return null;
        }

        try
        {
            // Attempt to query UserInfo - this may fail if service account doesn't have permission
            // but it's worth trying as it's standard OIDC
            var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
            request.Headers.Add("Authorization", $"Bearer {serviceAccountToken}");
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var userInfo = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                if (userInfo.TryGetProperty("sub", out var subElement))
                {
                    var sub = subElement.GetString();
                    _logger.LogInformation("Retrieved user sub from UserInfo endpoint: {Sub}", sub);
                    return sub;
                }
            }
            else
            {
                _logger.LogDebug("UserInfo endpoint query failed (expected if service account lacks permissions). Status: {Status}", response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error querying UserInfo endpoint (this is optional and may not be supported with service account tokens)");
        }

        // Fallback: Try to use Admin API if this appears to be Keycloak
        // This is IdP-specific but may be necessary for some providers
        return await TryGetUserIdFromAdminApiAsync(usernameOrEmail, serviceAccountToken, discovery, cancellationToken);
    }

    /// <summary>
    /// Fallback method: Attempts to get user ID from IdP-specific Admin API.
    /// Currently supports Keycloak. Can be extended for other IdPs as needed.
    /// </summary>
    private async Task<string?> TryGetUserIdFromAdminApiAsync(string usernameOrEmail, string serviceAccountToken, OidcDiscoveryDocument discovery, CancellationToken cancellationToken)
    {
        // Detect Keycloak by issuer pattern (contains /realms/)
        if (string.IsNullOrEmpty(discovery.Issuer) || !discovery.Issuer.Contains("/realms/", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("Not using Keycloak-specific Admin API (issuer doesn't match Keycloak pattern)");
            return null;
        }

        try
        {
            var baseUrl = _idpOptions.GetBaseUrl();
            var realm = GetRealmFromIssuer(discovery.Issuer);
            
            // Try to find user by exact username/email match using Keycloak Admin API
            var adminApiUrl = $"{baseUrl}/admin/realms/{realm}/users?exact=true&username={Uri.EscapeDataString(usernameOrEmail)}";
            
            var request = new HttpRequestMessage(HttpMethod.Get, adminApiUrl);
            request.Headers.Add("Authorization", $"Bearer {serviceAccountToken}");
            
            var response = await _httpClient.SendAsync(request, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var users = await response.Content.ReadFromJsonAsync<JsonElement[]>(cancellationToken: cancellationToken);
                if (users != null && users.Length > 0)
                {
                    var user = users[0];
                    if (user.TryGetProperty("id", out var idElement))
                    {
                        var userId = idElement.GetString();
                        _logger.LogInformation("Found user ID via Keycloak Admin API: {UserId} for username/email: {UsernameOrEmail}", userId, usernameOrEmail);
                        return userId;
                    }
                }
            }
            
            // Try searching by email
            if (usernameOrEmail.Contains('@'))
            {
                adminApiUrl = $"{baseUrl}/admin/realms/{realm}/users?exact=true&email={Uri.EscapeDataString(usernameOrEmail)}";
                request = new HttpRequestMessage(HttpMethod.Get, adminApiUrl);
                request.Headers.Add("Authorization", $"Bearer {serviceAccountToken}");
                
                response = await _httpClient.SendAsync(request, cancellationToken);
                
                if (response.IsSuccessStatusCode)
                {
                    var users = await response.Content.ReadFromJsonAsync<JsonElement[]>(cancellationToken: cancellationToken);
                    if (users != null && users.Length > 0)
                    {
                        var user = users[0];
                        if (user.TryGetProperty("id", out var idElement))
                        {
                            var userId = idElement.GetString();
                            _logger.LogInformation("Found user ID via Keycloak Admin API: {UserId} for email: {UsernameOrEmail}", userId, usernameOrEmail);
                            return userId;
                        }
                    }
                }
            }
            
            _logger.LogDebug("Could not find user ID via Keycloak Admin API for: {UsernameOrEmail}", usernameOrEmail);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error querying Keycloak Admin API for user ID: {UsernameOrEmail} (this is optional)", usernameOrEmail);
            return null;
        }
    }

    private async Task<string?> GetTokenSubjectAsync(string accessToken, CancellationToken cancellationToken)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (handler.CanReadToken(accessToken))
            {
                var token = handler.ReadJwtToken(accessToken);
                return token.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            }
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not extract subject from token");
            return null;
        }
    }

    private string GetRealmFromIssuer(string? issuer)
    {
        if (string.IsNullOrEmpty(issuer))
        {
            return "passkeysample"; // Default fallback for Keycloak
        }
        
        // Extract realm from Keycloak issuer URL: https://keycloak:8443/realms/passkeysample
        var parts = issuer.Split(new[] { "/realms/" }, StringSplitOptions.None);
        if (parts.Length == 2)
        {
            return parts[1].TrimEnd('/');
        }
        
        return "passkeysample"; // Default fallback
    }
}

// Reuse existing OAuthTokenResponse class from AuthController
public class OAuthTokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }
    
    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }
    
    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; set; }
    
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
    
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }
}

