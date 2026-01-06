using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using PassKeySample.Api.Configuration;

namespace PassKeySample.Api.Services;

public class OidcIdpUserService : IIdpUserService
{
    private readonly IdentityProviderOptions _options;
    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    private readonly ILogger<OidcIdpUserService> _logger;

    public OidcIdpUserService(
        IdentityProviderOptions options,
        IHttpClientFactory httpClientFactory,
        IMemoryCache cache,
        ILogger<OidcIdpUserService> logger)
    {
        _options = options;
        _httpClient = httpClientFactory.CreateClient("IdpClient");
        _cache = cache;
        _logger = logger;
    }

    public async Task<bool> UserExistsAsync(string usernameOrEmail, CancellationToken cancellationToken = default)
    {
        var userId = await GetUserIdAsync(usernameOrEmail, cancellationToken);
        return userId != null;
    }

    public async Task<string?> GetUserIdAsync(string usernameOrEmail, CancellationToken cancellationToken = default)
    {
        // Check cache first
        var cacheKey = $"idp_user_{usernameOrEmail}";
        if (_cache.TryGetValue<string?>(cacheKey, out var cachedUserId))
        {
            return cachedUserId;
        }

        try
        {
            // Strategy 1: Try to get a token using password grant (if password is available)
            // This is a common way to verify user existence, but requires password
            // For now, we'll skip this and try other methods

            // Strategy 2: Use UserInfo endpoint if we can get a service account token
            // This requires service account credentials which may not be available
            // We'll implement this as a future enhancement

            // Strategy 3: For now, we'll assume user exists if we can't verify
            // In production, this should be configured based on IDP capabilities
            _logger.LogWarning(
                "User existence check not fully implemented. Assuming user exists: {UsernameOrEmail}. " +
                "In production, configure service account or use IDP-specific admin API.",
                usernameOrEmail);

            // Normalize to email format as the canonical user identifier
            // This ensures consistency: both username and email resolve to the same email-based userId
            // In production, this should query the IDP to get the actual user ID (sub claim)
            
            string normalizedUserId;
            if (usernameOrEmail.Contains('@'))
            {
                // It's already an email - use it (normalized to lowercase)
                normalizedUserId = usernameOrEmail.ToLowerInvariant().Trim();
            }
            else
            {
                // It's a username - convert to email format by appending default domain
                // For Keycloak, we'll use the realm domain pattern
                // In production, this should query the IDP to get the user's actual email
                var username = usernameOrEmail.ToLowerInvariant().Trim();
                // Use a default domain - in production, this should come from IDP configuration
                normalizedUserId = $"{username}@passkeysample.local";
                _logger.LogInformation("Converted username '{Username}' to email format: '{Email}'", usernameOrEmail, normalizedUserId);
            }
            
            // Cache the result (assume exists for now) with short expiration
            var cacheOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5),
                SlidingExpiration = TimeSpan.FromMinutes(2)
            };
            _cache.Set(cacheKey, normalizedUserId, cacheOptions);

            // Return normalized user identifier (email format)
            // In a real implementation, this would query the IDP to get the actual user ID (sub claim)
            // which would be the same regardless of whether username or email is provided
            return normalizedUserId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check if user exists: {UsernameOrEmail}", usernameOrEmail);
            return null;
        }
    }

    private async Task<string?> GetServiceAccountTokenAsync(CancellationToken cancellationToken)
    {
        // This would use client credentials grant to get a service account token
        // For now, return null as service account may not be configured
        // TODO: Implement service account token retrieval when credentials are available
        return null;
    }
}

