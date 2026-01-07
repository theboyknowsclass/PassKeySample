using System.Reflection;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using PassKeySample.Api.Attributes;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class Role1VersionController : ControllerBase
{
    /// <summary>
    /// Gets the API version. Requires authentication (Bearer token with DPoP validation) and role1.
    /// </summary>
    [HttpGet]
    [RequireAuthentication]
    [RequireRole("role1")]
    public ActionResult<Role1VersionDto> Get()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
        
        return Ok(new Role1VersionDto
        {
            Version = version,
            Message = "Role1 endpoint accessed successfully"
        });
    }
}

public record Role1VersionDto
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
    
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}

