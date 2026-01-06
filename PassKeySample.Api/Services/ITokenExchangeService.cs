namespace PassKeySample.Api.Services;

public interface ITokenExchangeService
{
    Task<OAuthTokenResponse?> ExchangeForUserTokenAsync(string usernameOrEmail, string userId, CancellationToken cancellationToken = default);
}

