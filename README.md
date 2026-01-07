# PassKey Sample API

A Dockerized .NET 8 Web API with HTTPS support, designed for a multi-service architecture with Keycloak as the identity provider.

## Prerequisites

- Docker Desktop (or Docker Engine + Docker Compose)
- .NET 8 SDK (for local development)
- OpenSSL (for certificate generation - will be installed automatically on Windows via winget)

## Certificate Management

This project uses a **Local Certificate Authority (CA)** approach for managing certificates across multiple services. This allows you to:

- ✅ Trust the CA once, and all service certificates are automatically trusted
- ✅ Generate separate certificates for each service (API, Frontend, Keycloak)
- ✅ Avoid browser security warnings across all services
- ✅ Scale to additional services easily

### Architecture

```
Local CA (ca.crt)
    ├── API Certificate (api.crt, api.pfx)
    ├── Frontend Certificate (frontend.crt)
    └── Keycloak Certificate (keycloak.crt)
```

### Setup Certificates

**Windows:**
```powershell
# Generate CA and all service certificates
.\setup-all-certs.ps1

# Trust the CA (run as Administrator)
.\scripts\trust-ca.ps1
```

**Linux/Mac:**
```bash
# Generate CA and all service certificates
./setup-all-certs.sh

# Trust the CA (may require sudo)
./scripts/trust-ca.sh
```

### Manual Certificate Generation

If you need to generate certificates individually:

1. **Generate CA:**
   ```powershell
   .\scripts\generate-ca.ps1
   ```

2. **Generate service certificates:**
   ```powershell
   .\scripts\generate-service-certs.ps1
   ```

3. **Trust the CA:**
   ```powershell
   .\scripts\trust-ca.ps1  # Run as Administrator
   ```

### Certificate Locations

- **CA Certificate:** `certs/ca/ca.crt`
- **API Certificate:** `certs/api/api.pfx` (for .NET) and `certs/api/api.crt`
- **Frontend Certificate:** `certs/frontend/frontend.crt`
- **Keycloak Certificate:** `certs/keycloak/keycloak.crt`

## Running the Application

### Run with Docker Compose

```bash
docker-compose up --build
```

The services will be available at:
- **API HTTPS:** https://localhost:5001
- **API HTTP:** http://localhost:5000 (redirects to HTTPS)
- **Keycloak HTTP:** http://localhost:8080
- **Keycloak HTTPS:** https://localhost:8443

### Keycloak Admin Console

- **URL:** http://localhost:8080 (or https://localhost:8443)
- **Username:** `admin`
- **Password:** `admin123`

### Keycloak Realm

The `passkeysample` realm is automatically imported on startup with:
- **Realm:** `passkeysample`
- **Client ID:** `passkeysample-api`
- **Client Secret:** `api-client-secret-change-in-production`
- **Users:**
  - `admin` / `admin123` (admin role)
  - `user1` / `user123` (role1)
  - `user2` / `user123` (role2)

## API Endpoints

- Swagger UI (Development): https://localhost:5001/swagger
- Version API: https://localhost:5001/api/version
- Identity Provider Config: https://localhost:5001/api/identityprovider/config
- OIDC Discovery: https://localhost:5001/api/identityprovider/discovery

## Configuration

### Identity Provider Configuration

The API is configured to work with any OIDC-compliant identity provider. Configuration is in `appsettings.json`:

```json
{
  "IdentityProvider": {
    "BaseUrl": "keycloak",
    "ClientId": "passkeysample-api",
    "ClientSecret": "api-client-secret-change-in-production",
    "UseHttps": true,
    "HttpPort": 8080,
    "HttpsPort": 8443,
    "UseOidcDiscovery": true,
    "OidcDiscoveryEndpoint": "/realms/passkeysample/.well-known/openid-configuration"
  }
}
```

### Runtime Configuration

You can override these settings via:
- Environment variables (using `__` for nested properties, e.g., `IdentityProvider__BaseUrl`)
- `appsettings.Development.json` for development overrides
- Docker environment variables in `docker-compose.yml`

### Switching Between HTTP and HTTPS

HTTPS is enabled by default to match production setup. To use HTTP (for development only), update `appsettings.json`:

```json
{
  "IdentityProvider": {
    "UseHttps": false,
    "HttpPort": 8080
  }
}
```

### Using a Different Identity Provider

The API is generic and works with any OIDC-compliant provider. Simply update the configuration:

```json
{
  "IdentityProvider": {
    "BaseUrl": "your-idp-hostname",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret",
    "OidcDiscoveryEndpoint": "/.well-known/openid-configuration"
  }
}
```

## Development

### Run Locally (without Docker)

```bash
cd PassKeySample.Api
dotnet run
```

Note: When running locally, update the `BaseUrl` in `appsettings.Development.json` to `localhost` instead of `keycloak`.

### Build Docker Image

```bash
docker build -t passkeysample-api -f PassKeySample.Api/Dockerfile .
```

## Architecture

### Services Organization

The API services are organized by domain for better maintainability and adherence to SOLID principles:

```
Services/
├── Authentication/     # JWT & DPoP validation
│   ├── IDPoPValidator.cs
│   ├── IJwtTokenValidator.cs
│   └── implementations
├── Identity/          # OIDC & Token Exchange
│   ├── IIdpUserService.cs
│   ├── ITokenExchangeService.cs
│   ├── OidcDiscoveryService.cs
│   └── implementations
└── WebAuthn/          # Passkey operations
    ├── IWebAuthnCredentialStore.cs
    ├── IWebAuthnService.cs
    └── implementations
```

**Key Features:**
- Domain-based organization (Authentication, Identity, WebAuthn)
- All interfaces documented with XML comments
- Follows Dependency Inversion Principle (DIP)
- Easy to test and mock

## Documentation

### Architecture & Design
- [Certificate Trust Architecture](docs/API_TO_KEYCLOAK_TRUST.md) - How certificate trust works between services
- [IdP-Agnostic Architecture](docs/IDP_AGNOSTIC_ARCHITECTURE.md) - OIDC-compliant identity provider integration
- [WebAuthn Credential Store](docs/WEBAUTHN_CREDENTIAL_STORE.md) - Passkey storage abstraction

### Developer Guides
- [Development Certificate Setup](docs/CERTIFICATE_MANAGEMENT.md) - How to generate and trust development certificates

## Notes

- The certificate password is set to `PassKeySample123!` for development purposes
- In production, use proper certificates and secure password management
- The `certs` directory is gitignored for security
- Keycloak admin credentials should be changed in production
- Client secrets should be stored securely (Azure Key Vault, AWS Secrets Manager, etc.)
