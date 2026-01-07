using System.Text;
using PassKeySample.Api.Attributes;
using PassKeySample.Api.Services.Authentication;

namespace PassKeySample.Api.Middleware;

public class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuthenticationMiddleware> _logger;

    public AuthenticationMiddleware(
        RequestDelegate next,
        ILogger<AuthenticationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check if endpoint explicitly requires authentication via attribute
        var endpoint = context.GetEndpoint();
        var requireAuthentication = endpoint?.Metadata.GetMetadata<RequireAuthenticationAttribute>() != null;
        var skipAuthentication = endpoint?.Metadata.GetMetadata<SkipAuthenticationAttribute>() != null;

        // If SkipAuthentication is present, skip validation
        if (skipAuthentication)
        {
            await _next(context);
            return;
        }

        // If endpoint doesn't explicitly require authentication, skip validation (opt-in model)
        // Swagger, /api/auth/, and other unmarked endpoints will automatically skip here
        if (!requireAuthentication)
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

        // All validation passed - add header to response
        context.Response.Headers.Append("X-DPoP-Validated", "true");
        
        // Store validation results in context for authorization middleware/controllers
        context.Items["JwtValidationResult"] = jwtValidationResult;
        context.Items["DPoPValidationResult"] = validationResult;

        await _next(context);
    }
}

