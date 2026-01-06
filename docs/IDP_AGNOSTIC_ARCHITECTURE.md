# IdP-Agnostic Architecture

This document explains how the PassKey Sample API is designed to work with any OIDC-compliant identity provider (IdP), not just Keycloak.

## Core Principles

1. **OIDC Discovery First**: All configuration is discovered via OIDC discovery endpoints (`.well-known/openid-configuration`)
2. **Standard OAuth/OIDC Protocols**: Uses RFC 8693 Token Exchange, OIDC UserInfo endpoint, and standard JWT validation
3. **Graceful Fallbacks**: Attempts multiple strategies, falling back to IdP-specific methods only when necessary
4. **No Hardcoded IdP Logic**: Avoids IdP-specific code paths except where absolutely necessary

## Token Exchange Strategy (IdP-Agnostic)

The Token Exchange service (`TokenExchangeService`) implements a multi-strategy approach:

### Strategy 1: Token Exchange with `requested_subject` (RFC 8693)

- **Standard**: RFC 8693 allows optional `requested_subject` parameter
- **Supported By**: ADFS, Azure AD, and other IdPs that fully support RFC 8693
- **Not Supported By**: Keycloak (in standard token exchange mode)

The implementation **always tries this first** to be compatible with IdPs that support it.

### Strategy 2: Token Exchange without `requested_subject`

- **Fallback**: If `requested_subject` fails, tries without it
- **Works With**: Requires impersonation policies to be configured in the IdP
- **Result**: May return service account token instead of user token (depends on IdP configuration)

### Strategy 3: User ID Resolution (IdP-Agnostic)

To determine the user's subject identifier for Token Exchange, the implementation uses:

1. **OIDC UserInfo Endpoint** (Standard OIDC)
   - Attempts to query `userinfo_endpoint` from discovery document
   - Works with any OIDC-compliant provider
   - May require service account to have appropriate permissions

2. **IdP-Specific Admin API** (Fallback, detected automatically)
   - **Keycloak**: Automatically detected via issuer pattern (`/realms/`)
   - **Other IdPs**: Can be extended as needed
   - Only used when standard OIDC methods don't work

## IdP Detection

The system detects IdP type automatically:

- **Keycloak**: Detected by issuer containing `/realms/` pattern
- **ADFS**: Standard OIDC issuer pattern (no special detection needed)
- **Azure AD**: Standard OIDC issuer pattern (no special detection needed)
- **Generic OIDC**: Uses standard OIDC discovery and endpoints

## Configuration Requirements

### Required (All IdPs)

1. **OIDC Discovery Endpoint**: Must provide standard `.well-known/openid-configuration`
2. **Token Endpoint**: Must support OAuth 2.0 client credentials grant
3. **Service Account**: Client must be configured with service account capabilities
4. **Token Exchange**: Client must have Token Exchange capability enabled

### Optional (IdP-Specific)

1. **Keycloak**: 
   - Enable "Standard token exchange" capability
   - Assign `impersonation` role from `realm-management` to service account (for user token generation)
   
2. **ADFS / Azure AD**:
   - Token Exchange with `requested_subject` typically works out-of-the-box
   - May require application permissions configured in Azure AD

## Extending for New IdPs

To add support for a new IdP:

1. **If it's OIDC-compliant**: Should work automatically with no code changes
2. **If it needs special handling**: Add detection logic in `TryGetUserIdFromAdminApiAsync()` method
3. **If Token Exchange works differently**: The multi-strategy approach should handle it, but you can add custom logic

## Testing with Different IdPs

### Keycloak
- Tested with Keycloak 26.2.0
- Requires manual configuration of impersonation roles (see `mocks/keycloak/SETUP_TOKEN_EXCHANGE.md`)

### ADFS
- Should work with Token Exchange + `requested_subject`
- No special configuration needed beyond standard OIDC setup

### Azure AD
- Should work with Token Exchange + `requested_subject`
- May require application permissions for Token Exchange

## Limitations

1. **User Token Generation**: After WebAuthn verification, generating a user token requires either:
   - Token Exchange with `requested_subject` support (not all IdPs)
   - Impersonation policies (requires manual configuration)
   - Admin API access (IdP-specific)

2. **User Lookup**: Finding a user's subject ID may require:
   - Admin API access (IdP-specific)
   - Service account with appropriate permissions
   - UserInfo endpoint access (may not work with service account tokens)

3. **Configuration Variance**: Each IdP has different capabilities and configuration requirements

## Future Enhancements

1. **Plugin Architecture**: Could add IdP-specific plugins for advanced features
2. **Configuration Templates**: Provide IdP-specific configuration examples
3. **Admin API Abstraction**: Create a generic interface for Admin API operations
4. **Token Generation Alternatives**: Investigate alternative methods for user token generation (e.g., custom grants)

