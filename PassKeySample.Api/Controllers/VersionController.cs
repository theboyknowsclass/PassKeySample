using System.Reflection;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using PassKeySample.Api.Services;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VersionController : ControllerBase
{
    /// <summary>
    /// Gets the API version. This endpoint requires authentication via DPoP and JWT token.
    /// </summary>
    [HttpGet]
    public ActionResult<VersionDto> Get()
    {
        // Extract JWT validation result from middleware (already validated)
        if (!HttpContext.Items.TryGetValue("JwtValidationResult", out var jwtResultObj) ||
            jwtResultObj is not JwtValidationResult jwtResult ||
            !jwtResult.IsValid)
        {
            return Unauthorized(new { Error = "Invalid or missing authentication token" });
        }

        // Extract DPoP validation result from middleware (already validated)
        if (!HttpContext.Items.TryGetValue("DPoPValidationResult", out var dpopResultObj) ||
            dpopResultObj is not DPoPValidationResult dpopResult ||
            !dpopResult.IsValid)
        {
            return Unauthorized(new { Error = "Invalid or missing DPoP proof" });
        }

        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
        
        // Extract user identifier - prefer sub, then preferred_username, then nameidentifier
        string? authenticatedUser = jwtResult.Subject;
        if (string.IsNullOrEmpty(authenticatedUser) && jwtResult.Claims != null)
        {
            if (jwtResult.Claims.TryGetValue("preferred_username", out var preferredUsername) && preferredUsername != null)
            {
                authenticatedUser = preferredUsername.ToString();
            }
            else if (jwtResult.Claims.TryGetValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", out var nameIdentifier) && nameIdentifier != null)
            {
                authenticatedUser = nameIdentifier.ToString();
            }
            else if (jwtResult.Claims.TryGetValue("sub", out var sub) && sub != null)
            {
                authenticatedUser = sub.ToString();
            }
        }
        
        // Return version along with authenticated user information
        return Ok(new VersionDto
        {
            Version = version,
            AuthenticatedUser = authenticatedUser,
            TokenIssuer = jwtResult.Issuer,
            TokenExpiresAt = jwtResult.ExpiresAt,
            DPoPValidated = dpopResult.IsValid,
            UserClaims = jwtResult.Claims
        });
    }
}

public record VersionDto
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
    
    [JsonPropertyName("authenticatedUser")]
    public string? AuthenticatedUser { get; init; }
    
    [JsonPropertyName("tokenIssuer")]
    public string? TokenIssuer { get; init; }
    
    [JsonPropertyName("tokenExpiresAt")]
    public DateTime? TokenExpiresAt { get; init; }
    
    [JsonPropertyName("dpopValidated")]
    public bool DPoPValidated { get; init; }
    
    [JsonPropertyName("userClaims")]
    public Dictionary<string, object>? UserClaims { get; init; }
}

