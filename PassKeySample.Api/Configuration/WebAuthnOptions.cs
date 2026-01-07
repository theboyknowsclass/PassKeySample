namespace PassKeySample.Api.Configuration;

/// <summary>
/// Configuration options for WebAuthn (Web Authentication) passkey functionality.
/// These settings control how the relying party (this application) interacts with authenticators.
/// </summary>
public class WebAuthnOptions
{
    /// <summary>
    /// The configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "WebAuthn";

    /// <summary>
    /// The Relying Party ID, typically the domain name of the application.
    /// This must match the domain where the application is hosted for passkeys to work.
    /// Passkeys are bound to this identifier and cannot be used on other domains.
    /// </summary>
    public string RpId { get; set; } = "localhost";

    /// <summary>
    /// A human-readable name for the Relying Party, displayed to users during
    /// passkey registration and authentication prompts.
    /// </summary>
    public string RpName { get; set; } = "PassKey Sample";

    /// <summary>
    /// The expected origin (scheme + domain + port) for WebAuthn requests.
    /// Used to validate that authentication requests originate from the correct source.
    /// Must match the URL where the frontend application is served.
    /// </summary>
    public string Origin { get; set; } = "https://localhost:3000";

    /// <summary>
    /// The timeout in milliseconds for WebAuthn operations (registration/authentication).
    /// After this duration, the browser will cancel the operation if the user hasn't responded.
    /// Default is 60000ms (60 seconds).
    /// </summary>
    public int Timeout { get; set; } = 60000;
}
