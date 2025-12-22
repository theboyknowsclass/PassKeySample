# Certificate Trust Direction

## Answer: No, Keycloak doesn't need to trust the API's certificate

When communication is **one-way: API → Keycloak**, the trust requirements are:

- ✅ **API needs to trust Keycloak's certificate** (or the CA that signed it)
- ❌ **Keycloak does NOT need to trust the API's certificate**

## How TLS/HTTPS Certificate Validation Works

When the API makes an HTTPS request to Keycloak:

```
API (Client)                    Keycloak (Server)
   |                                    |
   |--- HTTPS Request ----------------->|
   |                                    |
   |<-- Certificate (keycloak.crt) ----|
   |                                    |
   | [Validates certificate]            |
   | ✅ Trusts? Continue                |
   | ❌ Untrusted? Connection fails     |
```

**The client (API) validates the server's (Keycloak) certificate, not the other way around.**

## Configuration

### Using Our CA Approach

Since all certificates are signed by the same CA:
- If the API trusts the CA → it automatically trusts Keycloak's certificate
- No additional configuration needed!

### In Docker Containers

The API container needs access to the CA certificate to validate Keycloak's certificate. We'll mount the CA certificate into the container.

## When Would Keycloak Need to Trust the API?

Only if Keycloak makes HTTPS requests **back to the API**, such as:
- Back-channel logout callbacks
- Token validation callbacks
- Webhook callbacks

In typical OAuth/OIDC flows:
- API → Keycloak: Token requests, user info, token validation
- Keycloak → API: Usually not required (API validates tokens locally)

## Production Considerations

In production with proper certificates (Let's Encrypt, etc.):
- Certificates are signed by trusted public CAs
- No special configuration needed - .NET HttpClient trusts public CAs by default
- Only self-signed or private CA certificates require explicit trust

