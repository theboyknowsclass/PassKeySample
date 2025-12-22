using System.Net.Http.Json;
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
        _httpClient = httpClientFactory.CreateClient();
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

            _cachedDiscovery = await response.Content.ReadFromJsonAsync<OidcDiscoveryDocument>(cancellationToken: cancellationToken);
            
            _logger.LogInformation("Successfully fetched OIDC discovery document");
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
    public string? Issuer { get; set; }
    public string? AuthorizationEndpoint { get; set; }
    public string? TokenEndpoint { get; set; }
    public string? UserInfoEndpoint { get; set; }
    public string? EndSessionEndpoint { get; set; }
    public string? JwksUri { get; set; }
    public List<string>? ResponseTypesSupported { get; set; }
    public List<string>? SubjectTypesSupported { get; set; }
    public List<string>? IdTokenSigningAlgValuesSupported { get; set; }
    public List<string>? ScopesSupported { get; set; }
    public List<string>? ClaimsSupported { get; set; }
}

