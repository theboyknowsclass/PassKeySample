using Microsoft.AspNetCore.Mvc;
using PassKeySample.Api.Configuration;
using PassKeySample.Api.Services;

namespace PassKeySample.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class IdentityProviderController : ControllerBase
{
    private readonly IdentityProviderOptions _options;
    private readonly OidcDiscoveryService _discoveryService;
    private readonly ILogger<IdentityProviderController> _logger;

    public IdentityProviderController(
        IdentityProviderOptions options,
        OidcDiscoveryService discoveryService,
        ILogger<IdentityProviderController> logger)
    {
        _options = options;
        _discoveryService = discoveryService;
        _logger = logger;
    }

    [HttpGet("config")]
    public IActionResult GetConfiguration()
    {
        var config = new
        {
            BaseUrl = _options.BaseUrl,
            ClientId = _options.ClientId,
            UseHttps = _options.UseHttps,
            HttpPort = _options.HttpPort,
            HttpsPort = _options.HttpsPort,
            UseOidcDiscovery = _options.UseOidcDiscovery,
            ResolvedBaseUrl = _options.GetBaseUrl(),
            OidcDiscoveryUrl = _options.UseOidcDiscovery 
                ? _options.GetOidcDiscoveryUrl() 
                : null
        };

        return Ok(config);
    }

    [HttpGet("discovery")]
    public async Task<IActionResult> GetDiscoveryDocument()
    {
        try
        {
            var discovery = await _discoveryService.GetDiscoveryDocumentAsync();
            
            if (discovery == null)
            {
                return BadRequest(new { Error = "OIDC discovery is not enabled or failed to fetch" });
            }

            return Ok(discovery);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get OIDC discovery document");
            return StatusCode(500, new { Error = "Failed to fetch OIDC discovery document", Message = ex.Message });
        }
    }
}

