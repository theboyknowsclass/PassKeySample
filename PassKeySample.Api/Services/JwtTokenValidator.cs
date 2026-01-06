using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using PassKeySample.Api.Configuration;

namespace PassKeySample.Api.Services;

public class JwtTokenValidator : IJwtTokenValidator
{
    private readonly OidcDiscoveryService _discoveryService;
    private readonly IdentityProviderOptions _idpOptions;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<JwtTokenValidator> _logger;
    private ConfigurationManager<OpenIdConnectConfiguration>? _configurationManager;
    private readonly SemaphoreSlim _configManagerLock = new(1, 1);

    public JwtTokenValidator(
        OidcDiscoveryService discoveryService,
        IdentityProviderOptions idpOptions,
        IHttpClientFactory httpClientFactory,
        ILogger<JwtTokenValidator> logger)
    {
        _discoveryService = discoveryService;
        _idpOptions = idpOptions;
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _logger = logger;
    }

    public async Task<JwtValidationResult> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            // Get configuration manager (with caching and automatic refresh)
            var configManager = await GetConfigurationManagerAsync(cancellationToken);
            if (configManager == null)
            {
                return new JwtValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Failed to initialize OIDC configuration"
                };
            }

            // Get configuration (cached, refreshed automatically)
            var configuration = await configManager.GetConfigurationAsync(cancellationToken);

            // Parse token to get claims before validation
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
            {
                return new JwtValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Invalid token format"
                };
            }

            var jwtToken = handler.ReadJwtToken(token);

            // Log token claims for debugging
            var tokenAudiences = jwtToken.Audiences?.ToList() ?? new List<string>();
            var tokenIssuer = jwtToken.Issuer;

            // For access tokens, the audience might be:
            // 1. The client ID that requested the token (passkeysample-api)
            // 2. A resource identifier
            // 3. An account or realm identifier
            // We'll accept the client ID as a valid audience, but also log what we're validating against
            var validAudiences = new List<string> { _idpOptions.ClientId };
            
            // Also accept audience from the discovery document issuer (realm-based)
            if (!string.IsNullOrEmpty(configuration.Issuer))
            {
                // Extract realm name from issuer for Keycloak: https://keycloak:8443/realms/passkeysample
                if (configuration.Issuer.Contains("/realms/", StringComparison.OrdinalIgnoreCase))
                {
                    var realmParts = configuration.Issuer.Split(new[] { "/realms/" }, StringSplitOptions.None);
                    if (realmParts.Length == 2)
                    {
                        var realmName = realmParts[1].TrimEnd('/');
                        // Keycloak often uses realm name or account identifier as audience
                        validAudiences.Add(realmName);
                        validAudiences.Add($"account"); // Keycloak account audience
                    }
                }
            }

            _logger.LogInformation("Validating token. Issuer: {Issuer}, Token audiences: {Audiences}, Validating against: {ValidAudiences}", 
                tokenIssuer, string.Join(", ", tokenAudiences), string.Join(", ", validAudiences));

            // Validate token
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = configuration.Issuer,
                ValidateAudience = true,
                ValidAudiences = validAudiences, // Accept multiple possible audiences
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = configuration.SigningKeys,
                ClockSkew = TimeSpan.FromMinutes(5) // Allow 5 minute clock skew
            };

            SecurityToken validatedToken;
            var principal = handler.ValidateToken(token, validationParameters, out validatedToken);

            // Extract claims
            var claims = principal.Claims.ToDictionary(c => c.Type, c => (object)c.Value);
            
            // Extract subject - try multiple claim types for compatibility
            var subject = principal.FindFirst("sub")?.Value 
                ?? principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;
                
            var issuer = claims.ContainsKey("iss") ? claims["iss"]?.ToString() : null;
            
            DateTime? expiresAt = null;
            if (claims.ContainsKey("exp") && long.TryParse(claims["exp"]?.ToString(), out var expUnix))
            {
                expiresAt = DateTimeOffset.FromUnixTimeSeconds(expUnix).DateTime;
            }

            _logger.LogInformation("JWT token validated successfully. Subject: {Subject}, Issuer: {Issuer}", subject, issuer);

            return new JwtValidationResult
            {
                IsValid = true,
                Claims = claims,
                Subject = subject,
                Issuer = issuer,
                ExpiresAt = expiresAt
            };
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger.LogWarning(ex, "JWT token has expired");
            return new JwtValidationResult
            {
                IsValid = false,
                ErrorMessage = "Token has expired"
            };
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            _logger.LogWarning(ex, "JWT token signature is invalid");
            return new JwtValidationResult
            {
                IsValid = false,
                ErrorMessage = "Invalid token signature"
            };
        }
        catch (SecurityTokenInvalidIssuerException ex)
        {
            _logger.LogWarning(ex, "JWT token issuer is invalid");
            return new JwtValidationResult
            {
                IsValid = false,
                ErrorMessage = "Invalid token issuer"
            };
        }
        catch (SecurityTokenInvalidAudienceException ex)
        {
            _logger.LogWarning(ex, "JWT token audience is invalid");
            return new JwtValidationResult
            {
                IsValid = false,
                ErrorMessage = "Invalid token audience"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating JWT token");
            return new JwtValidationResult
            {
                IsValid = false,
                ErrorMessage = $"Token validation failed: {ex.Message}"
            };
        }
    }

    private async Task<ConfigurationManager<OpenIdConnectConfiguration>?> GetConfigurationManagerAsync(CancellationToken cancellationToken)
    {
        if (_configurationManager != null)
        {
            return _configurationManager;
        }

        await _configManagerLock.WaitAsync(cancellationToken);
        try
        {
            // Double-check after acquiring lock
            if (_configurationManager != null)
            {
                return _configurationManager;
            }

            // Get discovery document to find OIDC discovery endpoint
            var discovery = await _discoveryService.GetDiscoveryDocumentAsync(cancellationToken);
            if (discovery == null || string.IsNullOrEmpty(discovery.JwksUri))
            {
                _logger.LogError("OIDC discovery document is null or JWKS URI is missing");
                return null;
            }

            // ConfigurationManager needs the OIDC discovery endpoint (not JWKS URI) to get issuer
            // The JWKS endpoint only returns signing keys, not the full OIDC configuration with issuer
            var discoveryEndpointUrl = _idpOptions.GetOidcDiscoveryUrl();
            _logger.LogInformation("Using OIDC discovery endpoint for ConfigurationManager: {DiscoveryUrl}", discoveryEndpointUrl);

            // Create configuration manager with automatic refresh
            // Use the IdpClient HttpClient which has certificate validation configured
            var httpClient = _httpClientFactory.CreateClient("IdpClient");
            var documentRetriever = new HttpDocumentRetriever(httpClient)
            {
                RequireHttps = _idpOptions.UseHttps
            };
            
            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                discoveryEndpointUrl,
                new OpenIdConnectConfigurationRetriever(),
                documentRetriever)
            {
                AutomaticRefreshInterval = TimeSpan.FromHours(24), // Refresh every 24 hours
                RefreshInterval = TimeSpan.FromMinutes(60) // Minimum refresh interval
            };

            _logger.LogInformation("Initialized OIDC configuration manager with discovery endpoint: {DiscoveryUrl}", discoveryEndpointUrl);
            return _configurationManager;
        }
        finally
        {
            _configManagerLock.Release();
        }
    }
}

