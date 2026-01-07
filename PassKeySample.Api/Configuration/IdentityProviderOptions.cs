namespace PassKeySample.Api.Configuration;

/// <summary>
/// Configuration options for the external Identity Provider (IdP) integration.
/// Supports OIDC-compliant providers like Keycloak for token validation and user management.
/// </summary>
public class IdentityProviderOptions
{
    /// <summary>
    /// The configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "IdentityProvider";

    /// <summary>
    /// The base URL or hostname of the Identity Provider.
    /// Can include protocol and port, which will be normalized by GetBaseUrl().
    /// Example: "keycloak" for Docker networking or "localhost" for local development.
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// The OAuth 2.0 client identifier registered with the Identity Provider.
    /// Used for token exchange and client authentication.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// The OAuth 2.0 client secret for confidential client authentication.
    /// Required for token exchange operations with the Identity Provider.
    /// Should be stored securely and not committed to source control.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Whether to use HTTPS when communicating with the Identity Provider.
    /// Should be true in production environments.
    /// </summary>
    public bool UseHttps { get; set; } = true;

    /// <summary>
    /// The HTTP port of the Identity Provider when UseHttps is false.
    /// </summary>
    public int HttpPort { get; set; } = 8080;

    /// <summary>
    /// The HTTPS port of the Identity Provider when UseHttps is true.
    /// </summary>
    public int HttpsPort { get; set; } = 8443;

    /// <summary>
    /// Whether to use OIDC Discovery to automatically fetch endpoints and signing keys.
    /// When enabled, the application will query the well-known endpoint for configuration.
    /// </summary>
    public bool UseOidcDiscovery { get; set; } = true;

    /// <summary>
    /// The relative path to the OIDC discovery document.
    /// Appended to the base URL to form the full discovery endpoint.
    /// Standard value is "/.well-known/openid-configuration".
    /// </summary>
    public string OidcDiscoveryEndpoint { get; set; } = "/.well-known/openid-configuration";

    /// <summary>
    /// Gets the full base URL including protocol and port.
    /// Normalizes the BaseUrl by extracting the hostname and applying the correct protocol/port settings.
    /// </summary>
    /// <returns>The fully qualified base URL (e.g., "https://keycloak:8443").</returns>
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
    /// Gets the OIDC discovery endpoint URL.
    /// Combines the base URL with the discovery endpoint path.
    /// </summary>
    /// <returns>The full URL to the OIDC discovery document.</returns>
    /// <exception cref="InvalidOperationException">Thrown when OIDC discovery is disabled.</exception>
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
