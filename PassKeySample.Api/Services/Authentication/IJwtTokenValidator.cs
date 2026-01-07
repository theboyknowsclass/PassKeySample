namespace PassKeySample.Api.Services.Authentication;

/// <summary>
/// Defines the contract for validating JWT access tokens.
/// Validates tokens against the Identity Provider's signing keys and configuration.
/// </summary>
public interface IJwtTokenValidator
{
    /// <summary>
    /// Validates a JWT access token using OIDC discovery for signing keys.
    /// Checks signature, issuer, audience, and expiration.
    /// </summary>
    /// <param name="token">The JWT access token to validate.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Validation result with claims if successful, or error details if failed.</returns>
    Task<JwtValidationResult> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of JWT token validation.
/// </summary>
public class JwtValidationResult
{
    /// <summary>
    /// Whether the token is valid.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Error message if validation failed, null otherwise.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Claims extracted from the token if validation succeeded.
    /// </summary>
    public Dictionary<string, object>? Claims { get; set; }

    /// <summary>
    /// The subject (sub) claim identifying the user or client.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// The issuer (iss) claim identifying the token issuer.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The expiration time of the token.
    /// </summary>
    public DateTime? ExpiresAt { get; set; }
}

