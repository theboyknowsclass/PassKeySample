using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using PassKeySample.Api.Configuration;

namespace PassKeySample.Api.Services;

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

public class OidcDiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }
    
    [JsonPropertyName("authorization_endpoint")]
    public string? AuthorizationEndpoint { get; set; }
    
    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; set; }
    
    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; set; }
    
    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; set; }
    
    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; set; }
    
    [JsonPropertyName("response_types_supported")]
    public List<string>? ResponseTypesSupported { get; set; }
    
    [JsonPropertyName("subject_types_supported")]
    public List<string>? SubjectTypesSupported { get; set; }
    
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public List<string>? IdTokenSigningAlgValuesSupported { get; set; }
    
    [JsonPropertyName("scopes_supported")]
    public List<string>? ScopesSupported { get; set; }
    
    [JsonPropertyName("claims_supported")]
    public List<string>? ClaimsSupported { get; set; }
}

