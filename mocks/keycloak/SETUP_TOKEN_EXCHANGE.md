# Setting Up Token Exchange in Keycloak

This guide explains how to configure Token Exchange (RFC 8693) for the `passkeysample-api` client.

## Important Note

**Keycloak's Standard Token Exchange does NOT support the `requested_subject` parameter.** This means Token Exchange alone cannot directly obtain a user-specific token from a service account token. 

For user-specific tokens after WebAuthn authentication, you have two options:

### Option 1: Configure Impersonation Policies (Recommended)

Keycloak requires impersonation policies to allow a service account to obtain user tokens via Token Exchange. This must be configured via the Admin Console:

1. Login to Keycloak Admin Console: http://localhost:8080 (admin/admin123)
2. Navigate to: **Realm `passkeysample`** → **Clients** → **`passkeysample-api`**
3. Go to: **Service accounts roles** tab
4. Click **Assign role**
5. Filter by **realm-management** client
6. Assign the **impersonation** role to the service account
7. Click **Assign**

Then configure Token Exchange:
1. In the same client page, go to: **Client Settings** → **Capabilities** tab
2. Enable: **"Standard token exchange"**
3. Click **Save**

**Note:** Even with impersonation configured, Token Exchange without `requested_subject` will return a service account token, not a user token. You may need to use Keycloak's impersonation endpoint directly instead of Token Exchange.

### Option 2: Use Keycloak Admin API Directly (Current Implementation)

The current implementation queries Keycloak Admin API to find the user's Keycloak ID, then attempts Token Exchange. However, without `requested_subject` support, this will only work if impersonation policies are configured to allow automatic user token generation.

## Automatic Configuration

The realm configuration file (`passkeysample-realm.json`) includes:
- `token.exchange: true` attribute on the client
- Service accounts enabled
- Required client scopes

However, **impersonation roles must be assigned manually** via the Admin Console (see Option 1 above).

## Verification

After configuration, test Token Exchange by attempting a login. Check the API logs for:
- ✅ `"Successfully exchanged service token for user token via Token Exchange (RFC 8693) for user: {KeycloakUserId}"`
- ❌ If you see `"Parameter 'requested_subject' is not supported"`, this is expected - Keycloak doesn't support this parameter
- ❌ If Token Exchange returns a service account token instead of user token, impersonation policies need to be configured

## Alternative Approaches

If Token Exchange with impersonation doesn't meet your needs, consider:
1. Using Keycloak's Admin API to generate user tokens directly
2. Using a different OIDC provider that supports `requested_subject` (e.g., ADFS, Azure AD)
3. Implementing a custom token generation endpoint that uses Keycloak Admin API

