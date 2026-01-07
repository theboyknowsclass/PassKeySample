using System.Reflection;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using PassKeySample.Api.Attributes;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VersionController : ControllerBase
{
    /// <summary>
    /// Gets the API version. Requires authentication (Bearer token with DPoP validation).
    /// </summary>
    [HttpGet]
    [RequireAuthentication]
    public ActionResult<VersionDto> Get()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
        
        return Ok(new VersionDto
        {
            Version = version
        });
    }

    /// <summary>
    /// Gets the API version (admin only). Requires authentication (Bearer token with DPoP validation) and admin role.
    /// </summary>
    [HttpGet("admin")]
    [RequireAuthentication]
    [RequireRole("admin")]
    public ActionResult<VersionDto> GetAdmin()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
        
        return Ok(new VersionDto
        {
            Version = version
        });
    }
}

public record VersionDto
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
}

