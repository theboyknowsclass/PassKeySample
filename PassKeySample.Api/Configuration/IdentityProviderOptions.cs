namespace PassKeySample.Api.Configuration;

public class IdentityProviderOptions
{
    public const string SectionName = "IdentityProvider";
    
    public string BaseUrl { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public bool UseHttps { get; set; } = true;
    public int HttpPort { get; set; } = 8080;
    public int HttpsPort { get; set; } = 8443;
    public bool UseOidcDiscovery { get; set; } = true;
    public string OidcDiscoveryEndpoint { get; set; } = "/.well-known/openid-configuration";
    
    /// <summary>
    /// Gets the full base URL including protocol and port
    /// </summary>
    public string GetBaseUrl()
    {
        var protocol = UseHttps ? "https" : "http";
        var port = UseHttps ? HttpsPort : HttpPort;
        
        // Extract hostname from BaseUrl (remove protocol and port if present)
        var hostname = BaseUrl
            .Replace("http://", "")
            .Replace("https://", "");
        
        // Remove port if present
        var colonIndex = hostname.IndexOf(':');
        if (colonIndex > 0)
        {
            hostname = hostname.Substring(0, colonIndex);
        }
        
        return $"{protocol}://{hostname}:{port}";
    }
    
    /// <summary>
    /// Gets the OIDC discovery endpoint URL
    /// </summary>
    public string GetOidcDiscoveryUrl()
    {
        if (!UseOidcDiscovery)
        {
            throw new InvalidOperationException("OIDC discovery is not enabled");
        }
        
        var baseUrl = GetBaseUrl();
        return $"{baseUrl}{OidcDiscoveryEndpoint}";
    }
}

