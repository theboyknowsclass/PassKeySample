namespace PassKeySample.Api.Services.Identity;

/// <summary>
/// Defines the contract for OAuth 2.0 Token Exchange (RFC 8693).
/// Enables the API to obtain user tokens after successful passkey authentication.
/// </summary>
public interface ITokenExchangeService
{
    /// <summary>
    /// Exchanges service account credentials for a user-specific access token.
    /// Uses RFC 8693 Token Exchange to obtain tokens for the authenticated user.
    /// </summary>
    /// <param name="usernameOrEmail">The username or email of the authenticated user.</param>
    /// <param name="userId">The unique identifier of the authenticated user.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>OAuth token response containing access token, refresh token, etc., or null if exchange fails.</returns>
    Task<OAuthTokenResponse?> ExchangeForUserTokenAsync(string usernameOrEmail, string userId, CancellationToken cancellationToken = default);
}

