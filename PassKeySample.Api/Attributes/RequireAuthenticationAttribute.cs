namespace PassKeySample.Api.Attributes;

/// <summary>
/// Attribute to indicate that an endpoint requires authentication (Bearer token with DPoP validation).
/// Authentication is performed by AuthenticationMiddleware.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
public class RequireAuthenticationAttribute : Attribute
{
    // Marker attribute - authentication validation is performed by AuthenticationMiddleware
}

/// <summary>
/// Attribute to explicitly skip authentication for an endpoint.
/// Useful when an endpoint is in a controller that has RequireAuthentication at the controller level.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
public class SkipAuthenticationAttribute : Attribute
{
}

