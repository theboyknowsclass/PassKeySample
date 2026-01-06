# Keycloak Realm Configuration

This directory contains a minimal Keycloak realm configuration that is automatically imported when Keycloak starts in development mode.

## Realm File

- **File:** `passkeysample-realm.json`
- **Realm Name:** `passkeysample`
- **Import Location:** `/opt/keycloak/data/import` (mounted as volume)

## Minimal Configuration

The realm file contains only the essential configuration:

### Realm
- Name: `passkeysample`
- Enabled: `true`

### Client
- **Client ID:** `passkeysample-api`
- **Client Secret:** `api-client-secret-change-in-production`
- **Enabled Flows:** Standard Flow, Direct Access Grants, Service Accounts
- **Token Exchange:** Enabled via `token.exchange` attribute
- **Note:** In Keycloak 26.2+, after realm import, you may need to manually enable "Standard token exchange" capability in Client Settings → Capabilities tab

### Users

1. **Admin User:**
   - Username: `admin`
   - Password: `admin123`
   - Email: `admin@passkeysample.local`
   - Role: `admin`

2. **Regular User:**
   - Username: `user1`
   - Password: `user123`
   - Email: `user1@passkeysample.local`

## Modifying the Realm

1. Edit `passkeysample-realm.json`
2. Restart Keycloak: `docker-compose restart keycloak`
3. The realm will be re-imported on startup

**Note:** In development mode, Keycloak will re-import the realm on every startup. In production, you would typically configure realms through the admin console or use a different import mechanism.

