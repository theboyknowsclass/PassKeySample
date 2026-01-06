using Microsoft.Extensions.Caching.Memory;
using PassKeySample.Api.Models;

namespace PassKeySample.Api.Services;

/// <summary>
/// In-memory implementation of WebAuthn credential store using IMemoryCache.
/// This is a temporary implementation suitable for development/testing.
/// For production, use a persistent store implementation (e.g., database-backed).
/// </summary>
public class InMemoryWebAuthnCredentialStore : IWebAuthnCredentialStore
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<InMemoryWebAuthnCredentialStore> _logger;
    private const string CacheKeyPrefix = "webauthn_cred_";

    public InMemoryWebAuthnCredentialStore(
        IMemoryCache cache,
        ILogger<InMemoryWebAuthnCredentialStore> logger)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task StoreCredentialAsync(WebAuthnCredential credential, CancellationToken cancellationToken = default)
    {
        var key = GetCredentialKey(credential.UserId, credential.CredentialId);
        var cacheOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(365), // Credentials don't expire
            Priority = CacheItemPriority.NeverRemove
        };

        _cache.Set(key, credential, cacheOptions);
        
        // Also maintain a list of credential IDs for the user
        var userCredsKey = GetUserCredentialsKey(credential.UserId);
        if (_cache.TryGetValue<List<byte[]>>(userCredsKey, out var credIds))
        {
            if (!credIds!.Any(id => id.SequenceEqual(credential.CredentialId)))
            {
                credIds.Add(credential.CredentialId);
                _cache.Set(userCredsKey, credIds, cacheOptions);
            }
        }
        else
        {
            _cache.Set(userCredsKey, new List<byte[]> { credential.CredentialId }, cacheOptions);
        }

        _logger.LogInformation("Stored WebAuthn credential for user: {UserId}", credential.UserId);
        return Task.CompletedTask;
    }

    public Task<List<WebAuthnCredential>> GetCredentialsAsync(string userId, CancellationToken cancellationToken = default)
    {
        var userCredsKey = GetUserCredentialsKey(userId);
        if (!_cache.TryGetValue<List<byte[]>>(userCredsKey, out var credIds) || credIds == null)
        {
            return Task.FromResult(new List<WebAuthnCredential>());
        }

        var credentials = new List<WebAuthnCredential>();
        foreach (var credId in credIds)
        {
            var key = GetCredentialKey(userId, credId);
            if (_cache.TryGetValue<WebAuthnCredential>(key, out var credential) && credential != null)
            {
                credentials.Add(credential);
            }
        }

        return Task.FromResult(credentials);
    }

    public Task<WebAuthnCredential?> GetCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var key = GetCredentialKey(userId, credentialId);
        _cache.TryGetValue<WebAuthnCredential>(key, out var credential);
        return Task.FromResult(credential);
    }

    public Task UpdateCounterAsync(string userId, byte[] credentialId, uint counter, CancellationToken cancellationToken = default)
    {
        var key = GetCredentialKey(userId, credentialId);
        if (_cache.TryGetValue<WebAuthnCredential>(key, out var credential) && credential != null)
        {
            credential.Counter = counter;
            credential.LastUsedAt = DateTime.UtcNow;
            _cache.Set(key, credential);
        }

        return Task.CompletedTask;
    }

    public Task DeleteCredentialAsync(string userId, byte[] credentialId, CancellationToken cancellationToken = default)
    {
        var key = GetCredentialKey(userId, credentialId);
        _cache.Remove(key);

        // Remove from user's credential list
        var userCredsKey = GetUserCredentialsKey(userId);
        if (_cache.TryGetValue<List<byte[]>>(userCredsKey, out var credIds))
        {
            credIds!.RemoveAll(id => id.SequenceEqual(credentialId));
            if (credIds.Count == 0)
            {
                _cache.Remove(userCredsKey);
            }
            else
            {
                _cache.Set(userCredsKey, credIds);
            }
        }

        _logger.LogInformation("Deleted WebAuthn credential for user: {UserId}", userId);
        return Task.CompletedTask;
    }

    private static string GetCredentialKey(string userId, byte[] credentialId)
    {
        var credIdBase64 = Convert.ToBase64String(credentialId);
        return $"{CacheKeyPrefix}{userId}_{credIdBase64}";
    }

    private static string GetUserCredentialsKey(string userId)
    {
        return $"{CacheKeyPrefix}user_{userId}_list";
    }
}

