namespace PassKeySample.Api.Attributes;

/// <summary>
/// Attribute that requires the user to have at least one of the specified roles.
/// Role checking is performed by AuthorizationMiddleware.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class RequireRoleAttribute : Attribute
{
    public string[] Roles { get; }

    public RequireRoleAttribute(params string[] roles)
    {
        Roles = roles ?? throw new ArgumentNullException(nameof(roles));
        if (Roles.Length == 0)
        {
            throw new ArgumentException("At least one role must be specified", nameof(roles));
        }
    }
}

