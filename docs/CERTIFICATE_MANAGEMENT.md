# Development Certificate Setup Guide

## Overview

This project uses a **Local Certificate Authority (CA)** approach for managing HTTPS certificates across multiple services. This is the recommended approach for development environments with multiple services.

## Why Use a CA?

### Benefits

1. **Single Trust Point**: Trust the CA once, and all certificates signed by it are automatically trusted
2. **Scalability**: Easy to add new services without managing individual certificates
3. **Consistency**: All certificates follow the same security standards
4. **No Browser Warnings**: Once the CA is trusted, all services work without security warnings

### Alternative Approaches

1. **Individual Self-Signed Certificates**: Each service has its own certificate
   - ❌ Must trust each certificate individually
   - ❌ More maintenance overhead
   - ✅ Simpler initial setup

2. **Wildcard Certificate**: Single certificate for all services
   - ✅ Single certificate to manage
   - ❌ Less flexible for different domains
   - ❌ All services share the same certificate

3. **Reverse Proxy with Single Certificate**: Nginx/Traefik terminates TLS
   - ✅ Services communicate internally over HTTP
   - ✅ Single certificate at the edge
   - ❌ More complex architecture
   - ✅ **Recommended for production**

## Certificate Structure

```
certs/
├── ca/
│   ├── ca.key          # CA private key (keep secure!)
│   ├── ca.crt          # CA certificate (trust this)
│   └── ca.conf         # CA configuration
├── api/
│   ├── api.key         # API private key
│   ├── api.crt         # API certificate
│   ├── api.csr         # Certificate signing request
│   └── api.pfx         # PFX format for .NET
├── frontend/
│   ├── frontend.key
│   ├── frontend.crt
│   └── frontend.csr
└── keycloak/
    ├── keycloak.key
    ├── keycloak.crt
    └── keycloak.csr
```

## Service-Specific Configuration

### API (.NET)

- **Format**: PFX (PKCS#12) for .NET Kestrel
- **Password**: `PassKeySample123!` (development only)
- **Usage**: Mounted in Docker container at `/https/api/api.pfx`
- **Configuration**: Set via `ASPNETCORE_Kestrel__Certificates__Default__Path`

### Frontend (Nginx)

- **Format**: CRT + KEY (PEM format)
- **Usage**: Configured in nginx.conf
- **Example nginx config**:
  ```nginx
  server {
      listen 443 ssl;
      ssl_certificate /certs/frontend/frontend.crt;
      ssl_certificate_key /certs/frontend/frontend.key;
      # ...
  }
  ```

### Keycloak

- **Format**: CRT + KEY (PEM format)
- **Usage**: Configured via Keycloak's HTTPS settings
- **Documentation**: [Keycloak HTTPS Configuration](https://www.keycloak.org/server/enabletls)

## Adding a New Service

1. **Add service name to generation script:**
   ```powershell
   # In scripts/generate-service-certs.ps1
   $Services = @("api", "frontend", "keycloak", "newservice")
   ```

2. **Add service-specific configuration:**
   ```powershell
   # Add case in switch statement
   "newservice" { "DNS:localhost,DNS:newservice.localhost,IP:127.0.0.1" }
   ```

3. **Regenerate certificates:**
   ```powershell
   .\scripts\generate-service-certs.ps1
   ```

4. **Update docker-compose.yml** to mount the certificate:
   ```yaml
   volumes:
     - ./certs/newservice:/certs:ro
   ```

## Trusting the CA

### Windows

```powershell
# Run as Administrator
Import-Certificate -FilePath "certs\ca\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

Or use the provided script:
```powershell
.\scripts\trust-ca.ps1  # Run as Administrator
```

### Linux

```bash
sudo cp certs/ca/ca.crt /usr/local/share/ca-certificates/passkeysample-ca.crt
sudo update-ca-certificates
```

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca/ca.crt
```

### Docker Containers

If services need to trust the CA (e.g., for inter-service communication):

```yaml
volumes:
  - ./certs/ca/ca.crt:/usr/local/share/ca-certificates/passkeysample-ca.crt:ro
```

Then in the container:
```bash
update-ca-certificates  # Linux
```

## Production Considerations

⚠️ **Important**: The CA approach is for **development only**. For production:

1. **Use a Reverse Proxy**: Nginx or Traefik with Let's Encrypt certificates
2. **Proper Domain Names**: Use real domains, not localhost
3. **Certificate Management**: Use ACME (Let's Encrypt) or enterprise PKI
4. **Internal Communication**: Services can communicate over HTTP internally, with TLS termination at the edge
5. **Secrets Management**: Store certificates securely (Azure Key Vault, AWS Secrets Manager, etc.)

## Troubleshooting

### Certificate Not Trusted

- Verify CA is in trusted root store
- Check certificate chain: `openssl verify -CAfile certs/ca/ca.crt certs/api/api.crt`
- Clear browser cache and restart browser

### Certificate Expired

- CA is valid for 10 years
- Service certificates are valid for 1 year
- Regenerate: `.\scripts\generate-service-certs.ps1`

### OpenSSL Not Found

- **Windows**: Script will attempt to install via winget
- **Manual**: Download from [Shining Light OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)
- **Linux**: `sudo apt-get install openssl` (Ubuntu/Debian) or `sudo yum install openssl` (RHEL/CentOS)
- **macOS**: `brew install openssl`

### .NET Certificate Issues

- Verify PFX password matches: `PassKeySample123!`
- Check file path in docker-compose.yml
- Ensure certificate has correct Subject Alternative Names (SANs)

## Security Notes

- ⚠️ **Never commit** the `certs/` directory to git (already in .gitignore)
- ⚠️ **Keep CA private key secure** - if compromised, regenerate everything
- ⚠️ **Development only** - these certificates are self-signed and not suitable for production
- ✅ CA certificate can be shared (public)
- ✅ Service certificates can be shared within the team (development)

