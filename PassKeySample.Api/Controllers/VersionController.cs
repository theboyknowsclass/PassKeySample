using System.Reflection;
using Microsoft.AspNetCore.Mvc;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VersionController : ControllerBase
{
    [HttpGet]
    public VersionDto Get()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
        return new VersionDto { Version = version };
    }
}

public record VersionDto
{
    public string Version { get; init; } = string.Empty;
}

