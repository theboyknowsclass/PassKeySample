namespace PassKeySample.Api.Services.Authentication;

/// <summary>
/// Defines the contract for validating DPoP (Demonstrating Proof-of-Possession) proofs.
/// DPoP binds access tokens to a specific client by requiring proof of private key possession.
/// See RFC 9449 for the DPoP specification.
/// </summary>
public interface IDPoPValidator
{
    /// <summary>
    /// Validates a DPoP proof JWT against the current request context.
    /// </summary>
    /// <param name="dpopProof">The DPoP proof JWT from the DPoP header.</param>
    /// <param name="accessToken">The access token being used (for 'ath' claim validation).</param>
    /// <param name="httpMethod">The HTTP method of the request (must match 'htm' claim).</param>
    /// <param name="httpUrl">The HTTP URL of the request (must match 'htu' claim).</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Validation result indicating success/failure and any extracted claims.</returns>
    Task<DPoPValidationResult> ValidateDPoPProofAsync(string dpopProof, string accessToken, string httpMethod, string httpUrl, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of DPoP proof validation.
/// </summary>
public class DPoPValidationResult
{
    /// <summary>
    /// Whether the DPoP proof is valid.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Error message if validation failed, null otherwise.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Claims extracted from the DPoP proof JWT if validation succeeded.
    /// </summary>
    public Dictionary<string, object>? Claims { get; set; }
}

