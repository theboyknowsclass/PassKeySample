namespace PassKeySample.Api.Services;

public interface IJwtTokenValidator
{
    Task<JwtValidationResult> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);
}

public class JwtValidationResult
{
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }
    public Dictionary<string, object>? Claims { get; set; }
    public string? Subject { get; set; }
    public string? Issuer { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

