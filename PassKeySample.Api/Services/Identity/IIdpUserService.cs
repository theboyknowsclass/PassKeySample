namespace PassKeySample.Api.Services.Identity;

/// <summary>
/// Defines the contract for querying user information from the Identity Provider.
/// Used to verify user existence and retrieve user identifiers before passkey operations.
/// </summary>
public interface IIdpUserService
{
    /// <summary>
    /// Checks whether a user exists in the Identity Provider.
    /// </summary>
    /// <param name="usernameOrEmail">The username or email address to look up.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>True if the user exists, false otherwise.</returns>
    Task<bool> UserExistsAsync(string usernameOrEmail, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the unique user identifier (subject) from the Identity Provider.
    /// </summary>
    /// <param name="usernameOrEmail">The username or email address to look up.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The user's unique identifier if found, null otherwise.</returns>
    Task<string?> GetUserIdAsync(string usernameOrEmail, CancellationToken cancellationToken = default);
}

