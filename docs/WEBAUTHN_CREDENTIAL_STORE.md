# WebAuthn Credential Store Abstraction

This document explains the credential store abstraction pattern used in the PassKey Sample API.

## Architecture

The credential store uses the **Strategy Pattern** to abstract storage implementation:

```
IWebAuthnCredentialStore (Interface)
└── InMemoryWebAuthnCredentialStore (In-memory implementation for dev/testing)
```

## Interface

`IWebAuthnCredentialStore` defines the contract for storing and retrieving WebAuthn credentials:

- `StoreCredentialAsync()` - Store a new credential
- `GetCredentialsAsync()` - Get all credentials for a user
- `GetCredentialAsync()` - Get a specific credential
- `UpdateCounterAsync()` - Update signature counter (for replay attack prevention)
- `DeleteCredentialAsync()` - Delete a credential

## Current Implementation

### InMemoryWebAuthnCredentialStore

- **Purpose**: Development and testing
- **Storage**: Uses `IMemoryCache` (in-memory, not persistent)
- **Limitations**: 
  - Data is lost on application restart
  - Not suitable for production
  - No data persistence

## Creating a Persistent Implementation

For production use, implement `IWebAuthnCredentialStore` with your preferred storage backend.

### Example: Entity Framework Implementation

```csharp
public class DatabaseWebAuthnCredentialStore : IWebAuthnCredentialStore
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<DatabaseWebAuthnCredentialStore> _logger;

    public DatabaseWebAuthnCredentialStore(
        ApplicationDbContext context,
        ILogger<DatabaseWebAuthnCredentialStore> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task StoreCredentialAsync(
        WebAuthnCredential credential, 
        CancellationToken cancellationToken = default)
    {
        _context.WebAuthnCredentials.Add(credential);
        await _context.SaveChangesAsync(cancellationToken);
        _logger.LogInformation("Stored WebAuthn credential for user: {UserId}", credential.UserId);
    }

    public async Task<List<WebAuthnCredential>> GetCredentialsAsync(
        string userId, 
        CancellationToken cancellationToken = default)
    {
        return await _context.WebAuthnCredentials
            .Where(c => c.UserId == userId)
            .ToListAsync(cancellationToken);
    }

    // Implement other methods...
}
```

### Registration

Update `Program.cs`:

```csharp
// Replace the in-memory store:
// builder.Services.AddScoped<IWebAuthnCredentialStore, InMemoryWebAuthnCredentialStore>();

// With your persistent implementation:
builder.Services.AddScoped<IWebAuthnCredentialStore, DatabaseWebAuthnCredentialStore>();
```

## Benefits of This Abstraction

1. **Testability**: Easy to mock `IWebAuthnCredentialStore` for unit tests
2. **Flexibility**: Swap storage implementations without changing business logic
3. **Separation of Concerns**: Storage logic is isolated from authentication logic
4. **SOLID Principles**: Follows Dependency Inversion Principle (DIP)

## Notes

- The interface is storage-agnostic - it doesn't know about databases, caches, etc.
- All implementations are registered via Dependency Injection
- Located in `PassKeySample.Api/Services/WebAuthn/` following domain-based organization
- The consuming code (`WebAuthnService`, `AuthController`) only depends on the interface

