using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using PassKeySample.Api.Configuration;

namespace PassKeySample.Api.Services.Identity;

/// <summary>
/// Implements OAuth 2.0 Token Exchange (RFC 8693) for obtaining user tokens.
/// After successful passkey authentication, exchanges service credentials for user-specific tokens.
/// </summary>
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
            // IMPORTANT: Only use actual Keycloak user ID (UUID), not normalized email addresses
            var userSub = await TryGetUserIdFromUserInfoAsync(usernameOrEmail, serviceTokenResponse.AccessToken, discovery, cancellationToken);
            
            // Only use requestedSubject if we got a real user ID from Admin API
            // Don't use normalized email (userId parameter) as it's not a valid Keycloak user ID
            string? requestedSubject = null;
            if (!string.IsNullOrEmpty(userSub))
            {
                // Verify it looks like a UUID (Keycloak user IDs are UUIDs)
                // This prevents using normalized emails as requested_subject
                if (System.Guid.TryParse(userSub, out _))
                {
                    requestedSubject = userSub;
                    _logger.LogInformation("Using Keycloak user ID for requested_subject: {UserId}", requestedSubject);
                }
                else
                {
                    _logger.LogWarning("User ID from Admin API doesn't look like a UUID, skipping requested_subject: {UserId}", userSub);
                }
            }
            else
            {
                _logger.LogInformation("Could not retrieve Keycloak user ID for {UsernameOrEmail}. Will attempt token exchange without requested_subject.", usernameOrEmail);
            }
            
            var exchangeRequest = new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                { "client_id", _idpOptions.ClientId },
                { "client_secret", _idpOptions.ClientSecret },
                { "subject_token", serviceTokenResponse.AccessToken }, // Service account token
                { "subject_token_type", "urn:ietf:params:oauth:token-type:access_token" },
                { "scope", "openid profile email roles" } // Request user-specific scopes including roles for authorization
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
                    // Note: RFC 8693 Token Exchange is an "on-behalf-of" mechanism, but Keycloak implements
                    // it with impersonation semantics (token represents the user directly, not a service account acting on behalf)
                    // True OBO tokens would include an 'act' (actor) claim, which we don't expect here
                    var handler = new JwtSecurityTokenHandler();
                    if (handler.CanReadToken(tokenResponse.AccessToken))
                    {
                        var jwt = handler.ReadJwtToken(tokenResponse.AccessToken);
                        
                        // TODO: REMOVE - DEBUG CODE ONLY
                        var allClaims = string.Join(", ", jwt.Claims.Select(c => $"{c.Type}={c.Value}"));
                        _logger.LogInformation("DEBUG: Token Exchange returned token with claims: {Claims}", allClaims);
                        
                        // Check for realm_access.roles
                        var realmAccessClaim = jwt.Claims.FirstOrDefault(c => c.Type == "realm_access");
                        if (realmAccessClaim != null)
                        {
                            _logger.LogInformation("DEBUG: Found realm_access claim: {RealmAccess}", realmAccessClaim.Value);
                        }
                        
                        var preferredUsername = jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
                        var isServiceAccount = preferredUsername?.StartsWith("service-account-", StringComparison.OrdinalIgnoreCase) == true;
                        
                        // Check for service account token FIRST - this is the most reliable indicator
                        if (isServiceAccount)
                        {
                            _logger.LogError("Token Exchange returned service account token instead of user token. Keycloak impersonation is required. User: {UsernameOrEmail}, Token username: {PreferredUsername}", 
                                usernameOrEmail, preferredUsername);
                            
                            // TODO: REMOVE - DEBUG CODE ONLY
                            var allClaimsDebug = string.Join(", ", jwt.Claims.Select(c => $"{c.Type}={c.Value}"));
                            _logger.LogError("DEBUG: Service account token claims: {Claims}", allClaimsDebug);
                            
                            throw new InvalidOperationException(
                                $"Token Exchange returned service account token instead of user token. " +
                                $"Keycloak's standard token exchange does not support user impersonation even with the 'impersonation' role. " +
                                $"The service account has the 'impersonation' role, but Keycloak requires additional configuration. " +
                                $"Possible solutions: " +
                                $"1. Enable 'Full Scope Allowed' on the client, " +
                                $"2. Configure token exchange policies in Keycloak, " +
                                $"3. Use Keycloak's Admin API for impersonation (requires different approach). " +
                                $"Current token is for service account: {preferredUsername}");
                        }
                        
                        // If not a service account, check if it's a valid user token
                        var hasUserClaim = jwt.Claims.Any(c => c.Type == "email" || c.Type == "preferred_username");
                        var hasActorClaim = jwt.Claims.Any(c => c.Type == "act"); // OBO pattern would include actor claim
                        
                        if (hasUserClaim)
                        {
                            if (hasActorClaim)
                            {
                                _logger.LogInformation("Token Exchange returned OBO token (on-behalf-of pattern) with actor claim. User: {TokenSub}", tokenSub);
                            }
                            else
                            {
                                _logger.LogInformation("Successfully exchanged service token for user token via Token Exchange (RFC 8693) with impersonation semantics. User: {TokenSub}, Username: {PreferredUsername}", tokenSub, preferredUsername);
                            }
                            return tokenResponse;
                        }
                    }
                    
                    // Final check: Verify it's not a service account token before returning
                    var handler2 = new JwtSecurityTokenHandler();
                    if (handler2.CanReadToken(tokenResponse.AccessToken))
                    {
                        var jwt2 = handler2.ReadJwtToken(tokenResponse.AccessToken);
                        var preferredUsername2 = jwt2.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
                        
                        // TODO: REMOVE - DEBUG CODE ONLY
                        _logger.LogInformation("DEBUG: Final token check - preferred_username: {PreferredUsername}", preferredUsername2);
                        
                        if (preferredUsername2?.StartsWith("service-account-", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            _logger.LogError("Token Exchange returned service account token. Keycloak impersonation is required. User: {UsernameOrEmail}, Token username: {PreferredUsername}", 
                                usernameOrEmail, preferredUsername2);
                            
                            // TODO: REMOVE - DEBUG CODE ONLY
                            var allClaimsDebug2 = string.Join(", ", jwt2.Claims.Select(c => $"{c.Type}={c.Value}"));
                            _logger.LogError("DEBUG: Service account token claims: {Claims}", allClaimsDebug2);
                            
                            throw new InvalidOperationException(
                                $"Token Exchange returned service account token instead of user token. " +
                                $"Keycloak's standard token exchange does not support user impersonation even with the 'impersonation' role. " +
                                $"The service account has the 'impersonation' role, but Keycloak requires additional configuration. " +
                                $"Current token is for service account: {preferredUsername2}");
                        }
                    }
                    
                    _logger.LogInformation("Token Exchange succeeded. Token subject: {TokenSub}", tokenSub ?? "unknown");
                    return tokenResponse;
                }
            }

            // Strategy 2: If requested_subject failed, try without it (for IdPs that don't support it)
            var errorResponse = await response.Content.ReadAsStringAsync(cancellationToken);
            var hasRequestedSubject = exchangeRequest.ContainsKey("requested_subject");
            
            if (hasRequestedSubject && errorResponse.Contains("requested_subject", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Token Exchange with requested_subject failed (not supported by this IdP). Trying Keycloak impersonation API. Error: {Error}", errorResponse);
                
                // Strategy 2a: For Keycloak, use Admin API impersonation endpoint
                // This is Keycloak-specific but necessary since standard token exchange doesn't support requested_subject
                if (!string.IsNullOrEmpty(userSub) && System.Guid.TryParse(userSub, out _))
                {
                    var impersonationToken = await TryKeycloakImpersonationAsync(discovery, serviceTokenResponse.AccessToken, userSub, cancellationToken);
                    if (impersonationToken != null)
                    {
                        _logger.LogInformation("Successfully obtained user token via Keycloak impersonation API for user: {UserId}", userSub);
                        return impersonationToken;
                    }
                }
                
                // Strategy 2b: Fallback to token exchange without requested_subject (may return service account token)
                _logger.LogWarning("Keycloak impersonation failed, trying token exchange without requested_subject (may return service account token)");
                exchangeRequest.Remove("requested_subject");
                content = new FormUrlEncodedContent(exchangeRequest);
                response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);
                
                if (response.IsSuccessStatusCode)
                {
                    var tokenResponse = await response.Content.ReadFromJsonAsync<OAuthTokenResponse>(jsonOptions, cancellationToken: cancellationToken);
                    
                    // Verify it's actually a user token, not a service account token
                    if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.AccessToken))
                    {
                        var handler = new JwtSecurityTokenHandler();
                        if (handler.CanReadToken(tokenResponse.AccessToken))
                        {
                            var jwt = handler.ReadJwtToken(tokenResponse.AccessToken);
                            var preferredUsername = jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
                            var isServiceAccount = preferredUsername?.StartsWith("service-account-", StringComparison.OrdinalIgnoreCase) == true;
                            
                            if (isServiceAccount)
                            {
                                _logger.LogError("Token Exchange without requested_subject returned service account token. Keycloak impersonation is required. User: {UsernameOrEmail}, Token username: {PreferredUsername}", 
                                    usernameOrEmail, preferredUsername);
                                
                                // TODO: REMOVE - DEBUG CODE ONLY
                                var allClaims = string.Join(", ", jwt.Claims.Select(c => $"{c.Type}={c.Value}"));
                                _logger.LogError("DEBUG: Service account token claims: {Claims}", allClaims);
                                
                                throw new InvalidOperationException(
                                    "Token Exchange returned service account token instead of user token. " +
                                    "Keycloak's standard token exchange (RFC 8693) does NOT support user impersonation, " +
                                    "even with the 'impersonation' role assigned. The 'impersonation' role is for Admin API, not token exchange. " +
                                    "Solutions: " +
                                    "1. Enable 'Full Scope Allowed' on the client (Clients > passkeysample-api > Settings), " +
                                    "2. Configure Keycloak token exchange policies (if available in your Keycloak version), " +
                                    "3. Use a different authentication flow that doesn't require token exchange, " +
                                    "4. Use Keycloak's Admin API for impersonation (returns browser redirect, not programmatic token). " +
                                    "For WebAuthn flows, consider authenticating users directly with Keycloak instead of using token exchange.");
                            }
                        }
                    }
                    
                    _logger.LogInformation("Token Exchange succeeded without requested_subject.");
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
                { "scope", "openid profile email roles" } // Include roles scope for service account token
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
                else
                {
                    _logger.LogDebug("Keycloak Admin API returned empty user list for username search: {UsernameOrEmail}", usernameOrEmail);
                }
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Keycloak Admin API username search failed. Status: {Status}, Response: {Response}, Username: {UsernameOrEmail}", 
                    response.StatusCode, errorContent, usernameOrEmail);
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
                    else
                    {
                        _logger.LogDebug("Keycloak Admin API returned empty user list for email search: {UsernameOrEmail}", usernameOrEmail);
                    }
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                    _logger.LogWarning("Keycloak Admin API email search failed. Status: {Status}, Response: {Response}, Email: {UsernameOrEmail}", 
                        response.StatusCode, errorContent, usernameOrEmail);
                }
            }
            
            _logger.LogWarning("Could not find user ID via Keycloak Admin API for: {UsernameOrEmail}. This may cause token exchange to fail if requested_subject is required.", usernameOrEmail);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error querying Keycloak Admin API for user ID: {UsernameOrEmail} (this is optional)", usernameOrEmail);
            return null;
        }
    }

    /// <summary>
    /// Attempts to get a user token via Keycloak Admin API.
    /// Since Keycloak's standard token exchange doesn't support user impersonation,
    /// we use the Admin API to reset the user's password temporarily and then use
    /// Resource Owner Password Credentials grant to get a user token.
    /// 
    /// NOTE: This is a workaround. The proper solution would be to configure Keycloak's
    /// token exchange policies or use a different authentication flow.
    /// </summary>
    private async Task<OAuthTokenResponse?> TryKeycloakImpersonationAsync(
        OidcDiscoveryDocument discovery,
        string serviceAccountToken,
        string userId,
        CancellationToken cancellationToken)
    {
        // Keycloak's Admin API impersonation endpoint is for browser sessions, not programmatic tokens.
        // The standard token exchange doesn't support user impersonation even with the impersonation role.
        // 
        // Options:
        // 1. Use Admin API to reset password and use Resource Owner Password Credentials (not ideal, requires password)
        // 2. Configure Keycloak token exchange policies (requires Keycloak configuration)
        // 3. Use a different authentication flow entirely
        //
        // For now, we'll return null and let the caller handle the error with a clear message.
        // The user will need to configure Keycloak's token exchange policies or use a different approach.
        
        _logger.LogDebug("Keycloak Admin API impersonation is for browser sessions, not programmatic tokens. " +
                        "Keycloak's standard token exchange (RFC 8693) does not support user impersonation. " +
                        "This requires Keycloak-specific configuration or a different authentication approach.");
        
        return null;
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

/// <summary>
/// OAuth 2.0 token response from the Identity Provider.
/// </summary>
public class OAuthTokenResponse
{
    /// <summary>
    /// The access token for API authorization.
    /// </summary>
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }
    
    /// <summary>
    /// The token type (typically "Bearer").
    /// </summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }
    
    /// <summary>
    /// Token lifetime in seconds.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; set; }
    
    /// <summary>
    /// Refresh token for obtaining new access tokens.
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
    
    /// <summary>
    /// ID token containing user identity claims.
    /// </summary>
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }
}

