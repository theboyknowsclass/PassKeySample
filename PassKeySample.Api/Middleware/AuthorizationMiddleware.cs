using System.Text;
using PassKeySample.Api.Attributes;
using PassKeySample.Api.Services.Authentication;
using System.Security.Claims;

namespace PassKeySample.Api.Middleware;

public class AuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuthorizationMiddleware> _logger;

    public AuthorizationMiddleware(
        RequestDelegate next,
        ILogger<AuthorizationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check if endpoint requires role authorization
        var endpoint = context.GetEndpoint();
        var requireRoleAttributes = endpoint?.Metadata.GetOrderedMetadata<RequireRoleAttribute>() ?? Array.Empty<RequireRoleAttribute>();

        // If no role requirements, skip authorization
        if (requireRoleAttributes.Count == 0)
        {
            await _next(context);
            return;
        }

        // Ensure authentication was successful (checked by AuthenticationMiddleware)
        if (!context.Items.TryGetValue("JwtValidationResult", out var jwtResultObj) ||
            jwtResultObj is not JwtValidationResult jwtResult ||
            !jwtResult.IsValid)
        {
            _logger.LogWarning("Authorization attempted but authentication was not successful");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                System.Text.Json.JsonSerializer.Serialize(new { Error = "Authentication required" }),
                Encoding.UTF8);
            return;
        }

        // Extract roles from JWT claims
        // TODO: REMOVE - DEBUG CODE ONLY
        _logger.LogInformation("DEBUG: All JWT claims: {Claims}", 
            string.Join(", ", jwtResult.Claims?.Select(c => $"{c.Key}={c.Value}") ?? Array.Empty<string>()));
        
        var userRoles = ExtractRoles(jwtResult.Claims);
        
        // TODO: REMOVE - DEBUG CODE ONLY
        _logger.LogInformation("DEBUG: Extracted roles: {Roles}", string.Join(", ", userRoles));

        // Check if user has at least one role from any RequireRole attribute
        // (user needs at least one role from the combined list of all required roles)
        var allRequiredRoles = requireRoleAttributes.SelectMany(a => a.Roles).Distinct().ToList();
        var hasRequiredRole = allRequiredRoles.Any(requiredRole =>
            userRoles.Any(userRole =>
                string.Equals(userRole, requiredRole, StringComparison.OrdinalIgnoreCase)));

        if (!hasRequiredRole)
        {
            _logger.LogWarning("User does not have required role(s). Required: {RequiredRoles}, User has: {UserRoles}", 
                string.Join(", ", allRequiredRoles), string.Join(", ", userRoles));
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                System.Text.Json.JsonSerializer.Serialize(new 
                { 
                    Error = "Forbidden", 
                    Message = $"Access denied. Required role(s): {string.Join(", ", allRequiredRoles)}" 
                }),
                Encoding.UTF8);
            return;
        }

        await _next(context);
    }

    /// <summary>
    /// Extracts roles from JWT claims. Supports multiple claim formats:
    /// 1. "roles" - Array of role strings (standard)
    /// 2. "realm_access.roles" - Keycloak realm roles (JSON structure)
    /// 3. "resource_access.{client}.roles" - Keycloak client roles (JSON structure)
    /// 4. ClaimTypes.Role - Standard role claim type
    /// </summary>
    private static List<string> ExtractRoles(Dictionary<string, object>? claims)
    {
        var roles = new List<string>();

        if (claims == null)
        {
            return roles;
        }

        // Standard "roles" claim (array of strings)
        if (claims.TryGetValue("roles", out var rolesValue))
        {
            if (rolesValue is string[] rolesArray)
            {
                roles.AddRange(rolesArray);
            }
            else if (rolesValue is List<object> rolesList)
            {
                roles.AddRange(rolesList.Select(r => r.ToString() ?? string.Empty));
            }
            else if (rolesValue is string rolesString)
            {
                // Handle JSON-encoded array (common in Keycloak)
                if (rolesString.TrimStart().StartsWith("["))
                {
                    try
                    {
                        var parsed = System.Text.Json.JsonSerializer.Deserialize<string[]>(rolesString);
                        if (parsed != null)
                        {
                            roles.AddRange(parsed);
                        }
                    }
                    catch
                    {
                        // If JSON parsing fails, treat as single role
                        roles.Add(rolesString);
                    }
                }
                else
                {
                    roles.Add(rolesString);
                }
            }
        }

        // ClaimTypes.Role (standard ASP.NET Core role claim)
        if (claims.TryGetValue(ClaimTypes.Role, out var claimTypeRoleValue))
        {
            if (claimTypeRoleValue is string[] claimRolesArray)
            {
                roles.AddRange(claimRolesArray);
            }
            else if (claimTypeRoleValue is string claimRoleString)
            {
                roles.Add(claimRoleString);
            }
        }

        // Keycloak realm_access.roles (JSON structure)
        if (claims.TryGetValue("realm_access", out var realmAccessValue))
        {
            try
            {
                string? realmAccessJson = null;
                if (realmAccessValue is string jsonString)
                {
                    realmAccessJson = jsonString;
                }
                else
                {
                    realmAccessJson = System.Text.Json.JsonSerializer.Serialize(realmAccessValue);
                }

                if (!string.IsNullOrEmpty(realmAccessJson))
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(realmAccessJson);
                    if (doc.RootElement.TryGetProperty("roles", out var rolesElement) &&
                        rolesElement.ValueKind == System.Text.Json.JsonValueKind.Array)
                    {
                        foreach (var roleElement in rolesElement.EnumerateArray())
                        {
                            if (roleElement.ValueKind == System.Text.Json.JsonValueKind.String)
                            {
                                roles.Add(roleElement.GetString() ?? string.Empty);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Silently ignore parsing errors for realm_access
            }
        }

        // Remove duplicates and empty strings
        return roles
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}

