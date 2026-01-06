using System.Text;
using PassKeySample.Api.Services;

namespace PassKeySample.Api.Middleware;

public class DPoPValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<DPoPValidationMiddleware> _logger;
    private readonly IServiceProvider _serviceProvider;

    public DPoPValidationMiddleware(
        RequestDelegate next,
        ILogger<DPoPValidationMiddleware> logger,
        IServiceProvider serviceProvider)
    {
        _next = next;
        _logger = logger;
        _serviceProvider = serviceProvider;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip DPoP validation for certain paths
        var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
        if (path.StartsWith("/api/auth/") || 
            path.StartsWith("/swagger") || 
            path == "/")
        {
            await _next(context);
            return;
        }

        // Extract DPoP proof from DPoP header (RFC 9449)
        if (!context.Request.Headers.TryGetValue("DPoP", out var dpopHeader))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                System.Text.Json.JsonSerializer.Serialize(new { Error = "Missing DPoP header" }),
                Encoding.UTF8);
            return;
        }

        var dpopProof = dpopHeader.ToString();

        // Extract access token from Authorization: Bearer header
        if (!context.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                System.Text.Json.JsonSerializer.Serialize(new { Error = "Missing Authorization header" }),
                Encoding.UTF8);
            return;
        }

        var authHeaderValue = authHeader.ToString();
        if (!authHeaderValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                System.Text.Json.JsonSerializer.Serialize(new { Error = "Invalid Authorization scheme. Expected Bearer" }),
                Encoding.UTF8);
            return;
        }

        var accessToken = authHeaderValue.Substring(7).Trim();

        // Step 1: Validate JWT token first (signature, expiration, issuer, audience)
        var jwtValidator = context.RequestServices.GetRequiredService<IJwtTokenValidator>();
        var jwtValidationResult = await jwtValidator.ValidateTokenAsync(accessToken, context.RequestAborted);

        if (!jwtValidationResult.IsValid)
        {
            _logger.LogWarning("JWT token validation failed: {Error}", jwtValidationResult.ErrorMessage);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                System.Text.Json.JsonSerializer.Serialize(new { Error = "Invalid token", Details = jwtValidationResult.ErrorMessage }),
                Encoding.UTF8);
            return;
        }

        // Store JWT validation result in context for use by controllers
        context.Items["JwtValidationResult"] = jwtValidationResult;

        // Step 2: Validate DPoP proof (bound to the validated token)
        var httpMethod = context.Request.Method;
        var httpUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";

        var dpopValidator = context.RequestServices.GetRequiredService<IDPoPValidator>();
        var validationResult = await dpopValidator.ValidateDPoPProofAsync(
            dpopProof,
            accessToken,
            httpMethod,
            httpUrl,
            context.RequestAborted);

        if (!validationResult.IsValid)
        {
            _logger.LogWarning("DPoP validation failed: {Error}", validationResult.ErrorMessage);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                System.Text.Json.JsonSerializer.Serialize(new { Error = "DPoP validation failed", Details = validationResult.ErrorMessage }),
                Encoding.UTF8);
            return;
        }

        // Store validation result in context for use by controllers
        context.Items["DPoPValidationResult"] = validationResult;

        await _next(context);
    }
}

