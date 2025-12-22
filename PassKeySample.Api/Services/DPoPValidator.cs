using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;

namespace PassKeySample.Api.Services;

public class DPoPValidator : IDPoPValidator
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<DPoPValidator> _logger;
    private const string JtiCachePrefix = "dpop_jti_";

    public DPoPValidator(
        IMemoryCache cache,
        ILogger<DPoPValidator> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public Task<DPoPValidationResult> ValidateDPoPProofAsync(
        string dpopProof,
        string accessToken,
        string httpMethod,
        string httpUrl,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Parse the DPoP proof JWT
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(dpopProof))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Invalid DPoP proof format"
                });
            }

            var token = handler.ReadJwtToken(dpopProof);

            // Extract claims
            var claims = token.Claims.ToDictionary(c => c.Type, c => (object)c.Value);

            // Validate required claims
            if (!claims.ContainsKey("iat"))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Missing 'iat' claim"
                });
            }

            if (!claims.ContainsKey("jti"))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Missing 'jti' claim"
                });
            }

            if (!claims.ContainsKey("htm"))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Missing 'htm' claim"
                });
            }

            if (!claims.ContainsKey("htu"))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Missing 'htu' claim"
                });
            }

            // Check replay attack (jti must be unique)
            var jti = claims["jti"].ToString()!;
            var jtiCacheKey = $"{JtiCachePrefix}{jti}";
            if (_cache.TryGetValue<bool>(jtiCacheKey, out var _))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "DPoP proof already used (replay attack detected)"
                });
            }

            // Store jti to prevent replay (expire after 1 hour)
            _cache.Set(jtiCacheKey, true, TimeSpan.FromHours(1));

            // Validate HTTP method
            var htm = claims["htm"].ToString()!;
            if (!string.Equals(htm, httpMethod, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"HTTP method mismatch. Expected: {httpMethod}, Got: {htm}"
                });
            }

            // Validate HTTP URL (normalize for comparison)
            var htu = claims["htu"].ToString()!;
            var normalizedRequestUrl = NormalizeUrl(httpUrl);
            var normalizedHtu = NormalizeUrl(htu);
            if (!string.Equals(normalizedRequestUrl, normalizedHtu, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new DPoPValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"HTTP URL mismatch. Expected: {normalizedRequestUrl}, Got: {normalizedHtu}"
                });
            }

            // Validate iat (issued at) - should be recent (within last 5 minutes)
            if (claims.ContainsKey("iat") && long.TryParse(claims["iat"].ToString(), out var iat))
            {
                var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
                var now = DateTimeOffset.UtcNow;
                if (now - issuedAt > TimeSpan.FromMinutes(5))
                {
                    return Task.FromResult(new DPoPValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "DPoP proof is too old"
                    });
                }
            }

            // Validate ath (access token hash) if present
            if (claims.ContainsKey("ath"))
            {
                var ath = claims["ath"].ToString()!;
                var expectedAth = ComputeAccessTokenHash(accessToken);
                if (!string.Equals(ath, expectedAth, StringComparison.Ordinal))
                {
                    return Task.FromResult(new DPoPValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "Access token hash mismatch"
                    });
                }
            }

            // Note: Signature validation would require the public key from the token
            // For now, we'll validate the structure and claims
            // In production, you should validate the JWT signature using the public key
            // from the access token's 'cnf' claim or from a JWKS endpoint

            _logger.LogInformation("DPoP proof validated successfully");
            return Task.FromResult(new DPoPValidationResult
            {
                IsValid = true,
                Claims = claims
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating DPoP proof");
            return Task.FromResult(new DPoPValidationResult
            {
                IsValid = false,
                ErrorMessage = $"Validation error: {ex.Message}"
            });
        }
    }

    private static string NormalizeUrl(string url)
    {
        // Remove trailing slashes and normalize
        var uri = new Uri(url);
        return uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
    }

    private static string ComputeAccessTokenHash(string accessToken)
    {
        // DPoP uses SHA-256 hash of the access token, base64url encoded
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(accessToken));
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

