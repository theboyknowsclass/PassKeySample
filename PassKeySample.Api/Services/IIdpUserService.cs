namespace PassKeySample.Api.Services;

public interface IIdpUserService
{
    Task<bool> UserExistsAsync(string usernameOrEmail, CancellationToken cancellationToken = default);
    Task<string?> GetUserIdAsync(string usernameOrEmail, CancellationToken cancellationToken = default);
}

