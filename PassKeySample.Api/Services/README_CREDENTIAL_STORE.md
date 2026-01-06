# WebAuthn Credential Store Abstraction

This document explains the credential store abstraction pattern used in the PassKey Sample API.

## Architecture

The credential store uses the **Strategy Pattern** to abstract storage implementation:

```
IWebAuthnCredentialStore (Interface)
├── InMemoryWebAuthnCredentialStore (In-memory implementation)
└── PersistentWebAuthnCredentialStore (Abstract base for persistent implementations)
```

## Interface

`IWebAuthnCredentialStore` defines the contract for storing and retrieving WebAuthn credentials:

- `StoreCredentialAsync()` - Store a new credential
- `GetCredentialsAsync()` - Get all credentials for a user
- `GetCredentialAsync()` - Get a specific credential
- `UpdateCounterAsync()` - Update signature counter (for replay attack prevention)
- `DeleteCredentialAsync()` - Delete a credential

## Implementations

### InMemoryWebAuthnCredentialStore

- **Purpose**: Development and testing
- **Storage**: Uses `IMemoryCache` (in-memory, not persistent)
- **Limitations**: 
  - Data is lost on application restart
  - Not suitable for production
  - No data persistence

### PersistentWebAuthnCredentialStore

- **Purpose**: Base class for production implementations
- **Storage**: Abstract - implement your own persistent storage
- **Usage**: Inherit from this class and implement the abstract methods

## Creating a Persistent Implementation

### Example: Entity Framework Implementation

```csharp
public class DatabaseWebAuthnCredentialStore : PersistentWebAuthnCredentialStore
{
    private readonly ApplicationDbContext _context;

    public DatabaseWebAuthnCredentialStore(
        ApplicationDbContext context,
        ILogger<DatabaseWebAuthnCredentialStore> logger)
        : base(logger)
    {
        _context = context;
    }

    public override async Task StoreCredentialAsync(
        WebAuthnCredential credential, 
        CancellationToken cancellationToken = default)
    {
        _context.WebAuthnCredentials.Add(credential);
        await _context.SaveChangesAsync(cancellationToken);
        Logger.LogInformation("Stored WebAuthn credential for user: {UserId}", credential.UserId);
    }

    public override async Task<List<WebAuthnCredential>> GetCredentialsAsync(
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
- The consuming code (`WebAuthnService`, `AuthController`) only depends on the interface

