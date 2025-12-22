# API to Keycloak Certificate Trust

## Quick Answer

**No, Keycloak does NOT need to trust the API's certificate** when communication is one-way (API → Keycloak only).

**However, the API DOES need to trust Keycloak's certificate** (or the CA that signed it).

## How It Works

### Certificate Trust Direction

```
┌─────────────┐                    ┌──────────────┐
│     API     │                    │   Keycloak   │
│  (Client)   │                    │   (Server)   │
└──────┬──────┘                    └──────┬───────┘
       │                                   │
       │  HTTPS Request                   │
       │──────────────────────────────────>│
       │                                   │
       │  Sends Certificate                │
       │<──────────────────────────────────│
       │                                   │
       │  [Validates Certificate]          │
       │  ✅ Trusts? → Continue           │
       │  ❌ Untrusted? → Connection fails │
       │                                   │
```

**The client (API) validates the server's (Keycloak) certificate.**

### Our CA-Based Solution

Since we use a **Local Certificate Authority (CA)**:

1. **All certificates are signed by the same CA:**
   - API certificate ← signed by CA
   - Keycloak certificate ← signed by CA
   - Frontend certificate ← signed by CA

2. **If the API trusts the CA, it automatically trusts Keycloak:**
   - ✅ No additional configuration needed
   - ✅ Works for all services signed by the CA

## Configuration

### Docker Setup

The API container is configured to:

1. **Mount the CA certificate:**
   ```yaml
   volumes:
     - ./certs/ca/ca.crt:/usr/local/share/ca-certificates/passkeysample-ca.crt:ro
   ```

2. **Update CA trust store on startup:**
   - The Dockerfile includes an entrypoint script
   - Runs `update-ca-certificates` when the container starts
   - Adds the CA to the system's trust store

3. **.NET automatically uses the system trust store:**
   - `HttpClient` validates certificates using the system's CA store
   - No code changes needed!

### What This Means

When your API code makes HTTPS requests to Keycloak:

```csharp
var httpClient = new HttpClient();
var response = await httpClient.GetAsync("https://keycloak:8443/realms/myrealm/.well-known/openid-configuration");
// ✅ Works! API trusts Keycloak's certificate because it trusts the CA
```

## When Would Keycloak Need to Trust the API?

**Only if Keycloak makes HTTPS requests back to the API**, such as:

- ❌ **Not needed for typical OAuth/OIDC flows:**
  - Token requests (API → Keycloak)
  - User info requests (API → Keycloak)
  - Token validation (API validates tokens locally)

- ✅ **Would be needed for:**
  - Back-channel logout callbacks (Keycloak → API)
  - Token introspection callbacks (Keycloak → API)
  - Webhook callbacks (Keycloak → API)

## Production Considerations

In production with **public CA certificates** (Let's Encrypt, etc.):

- ✅ No special configuration needed
- ✅ .NET HttpClient trusts public CAs by default
- ✅ Only self-signed or private CA certificates require explicit trust

## Summary

| Scenario | API Trusts Keycloak? | Keycloak Trusts API? |
|----------|---------------------|---------------------|
| **API → Keycloak only** | ✅ **Required** | ❌ **Not needed** |
| **Bidirectional HTTPS** | ✅ Required | ✅ Required |
| **Production (public CA)** | ✅ Automatic | ✅ Automatic |

**For your use case (API → Keycloak only):**
- ✅ API container trusts CA → automatically trusts Keycloak
- ❌ Keycloak doesn't need to trust API's certificate

