using System.Reflection;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using PassKeySample.Api.Attributes;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class Role2VersionController : ControllerBase
{
    /// <summary>
    /// Gets the API version. Requires authentication (Bearer token with DPoP validation) and role2.
    /// </summary>
    [HttpGet]
    [RequireAuthentication]
    [RequireRole("role2")]
    public ActionResult<Role2VersionDto> Get()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
        
        return Ok(new Role2VersionDto
        {
            Version = version,
            Message = "Role2 endpoint accessed successfully"
        });
    }
}

public record Role2VersionDto
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
    
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}

