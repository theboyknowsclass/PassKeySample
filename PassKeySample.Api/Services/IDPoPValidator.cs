namespace PassKeySample.Api.Services;

public interface IDPoPValidator
{
    Task<DPoPValidationResult> ValidateDPoPProofAsync(string dpopProof, string accessToken, string httpMethod, string httpUrl, CancellationToken cancellationToken = default);
}

public class DPoPValidationResult
{
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }
    public Dictionary<string, object>? Claims { get; set; }
}

