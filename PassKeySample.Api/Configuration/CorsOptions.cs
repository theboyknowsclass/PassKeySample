namespace PassKeySample.Api.Configuration;

/// <summary>
/// Configuration options for Cross-Origin Resource Sharing (CORS) policy.
/// Controls which external origins can access the API and what methods/headers are permitted.
/// </summary>
public class CorsOptions
{
    /// <summary>
    /// The configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "Cors";

    /// <summary>
    /// List of allowed origins that can make cross-origin requests to this API.
    /// Should include the frontend application URL(s).
    /// Example: ["https://localhost:3000", "https://myapp.example.com"]
    /// </summary>
    public string[] AllowedOrigins { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Whether to allow any HTTP method (GET, POST, PUT, DELETE, etc.) in cross-origin requests.
    /// When false, specific methods must be configured separately.
    /// </summary>
    public bool AllowAnyMethod { get; set; } = true;

    /// <summary>
    /// Whether to allow any HTTP header in cross-origin requests.
    /// When false, specific headers must be configured separately.
    /// Required headers for this application include Authorization and DPoP.
    /// </summary>
    public bool AllowAnyHeader { get; set; } = true;

    /// <summary>
    /// Whether to allow credentials (cookies, authorization headers) in cross-origin requests.
    /// Must be true for authenticated API calls from the frontend.
    /// Note: When true, AllowedOrigins cannot use wildcard (*).
    /// </summary>
    public bool AllowCredentials { get; set; } = true;
}
