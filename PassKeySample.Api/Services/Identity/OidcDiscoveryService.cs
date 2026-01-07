using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using PassKeySample.Api.Configuration;

namespace PassKeySample.Api.Services.Identity;

/// <summary>
/// Fetches and caches the OIDC discovery document from the Identity Provider.
/// The discovery document contains endpoints and capabilities of the IdP.
/// </summary>
public class OidcDiscoveryService
{
    private readonly IdentityProviderOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILogger<OidcDiscoveryService> _logger;
    private OidcDiscoveryDocument? _cachedDiscovery;

    public OidcDiscoveryService(
        IdentityProviderOptions options,
        IHttpClientFactory httpClientFactory,
        ILogger<OidcDiscoveryService> logger)
    {
        _options = options;
        _httpClient = httpClientFactory.CreateClient("IdpClient");
        _logger = logger;
    }

    /// <summary>
    /// Retrieves the OIDC discovery document, using a cached copy if available.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The discovery document, or null if discovery is disabled or fails.</returns>
    public async Task<OidcDiscoveryDocument?> GetDiscoveryDocumentAsync(CancellationToken cancellationToken = default)
    {
        if (!_options.UseOidcDiscovery)
        {
            _logger.LogWarning("OIDC discovery is not enabled");
            return null;
        }

        if (_cachedDiscovery != null)
        {
            return _cachedDiscovery;
        }

        try
        {
            var discoveryUrl = _options.GetOidcDiscoveryUrl();
            _logger.LogInformation("Fetching OIDC discovery document from: {DiscoveryUrl}", discoveryUrl);

            var response = await _httpClient.GetAsync(discoveryUrl, cancellationToken);
            response.EnsureSuccessStatusCode();

            // Use JsonSerializerOptions with case-insensitive property matching
            // OIDC discovery documents use snake_case, but we've mapped them with JsonPropertyName attributes
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            
            _cachedDiscovery = await response.Content.ReadFromJsonAsync<OidcDiscoveryDocument>(options, cancellationToken);
            
            if (_cachedDiscovery != null)
            {
                _logger.LogInformation("Successfully fetched OIDC discovery document. TokenEndpoint: {TokenEndpoint}, JwksUri: {JwksUri}", 
                    _cachedDiscovery.TokenEndpoint, _cachedDiscovery.JwksUri);
            }
            
            return _cachedDiscovery;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch OIDC discovery document");
            throw;
        }
    }
}

/// <summary>
/// Represents the OIDC discovery document (/.well-known/openid-configuration).
/// Contains endpoints and capabilities of the Identity Provider.
/// </summary>
public class OidcDiscoveryDocument
{
    /// <summary>
    /// The issuer identifier for the IdP.
    /// </summary>
    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }
    
    /// <summary>
    /// URL of the authorization endpoint for user authentication.
    /// </summary>
    [JsonPropertyName("authorization_endpoint")]
    public string? AuthorizationEndpoint { get; set; }
    
    /// <summary>
    /// URL of the token endpoint for obtaining tokens.
    /// </summary>
    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; set; }
    
    /// <summary>
    /// URL of the userinfo endpoint for retrieving user claims.
    /// </summary>
    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; set; }
    
    /// <summary>
    /// URL of the end session endpoint for logout.
    /// </summary>
    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; set; }
    
    /// <summary>
    /// URL of the JSON Web Key Set containing signing keys.
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; set; }
    
    /// <summary>
    /// OAuth 2.0 response types supported by the IdP.
    /// </summary>
    [JsonPropertyName("response_types_supported")]
    public List<string>? ResponseTypesSupported { get; set; }
    
    /// <summary>
    /// Subject identifier types supported by the IdP.
    /// </summary>
    [JsonPropertyName("subject_types_supported")]
    public List<string>? SubjectTypesSupported { get; set; }
    
    /// <summary>
    /// Signing algorithms supported for ID tokens.
    /// </summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public List<string>? IdTokenSigningAlgValuesSupported { get; set; }
    
    /// <summary>
    /// OAuth 2.0 scopes supported by the IdP.
    /// </summary>
    [JsonPropertyName("scopes_supported")]
    public List<string>? ScopesSupported { get; set; }
    
    /// <summary>
    /// Claims that can be returned by the IdP.
    /// </summary>
    [JsonPropertyName("claims_supported")]
    public List<string>? ClaimsSupported { get; set; }
}

