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
- **Token Exchange:** Enabled via `standard.token.exchange.enabled` attribute in the realm configuration
- **Service Account Roles (Optional but Recommended):** 
  - `impersonation` role from `realm-management` client (enables token exchange to generate user tokens; without it, may return service account tokens)
  - `view-users` role from `realm-management` client (enables Admin API access to query user information; helps with user ID lookup)
  
  **Note:** These roles can be configured manually via Keycloak Admin Console or using the provided scripts in `scripts/configure-keycloak-service-account.*`

### Roles
- **role1:** For testing role-based authorization
- **role2:** For testing role-based authorization

### Users

1. **Admin User:**
   - Username: `admin`
   - Password: `admin123`
   - Email: `admin@passkeysample.local`
   - Role: `admin`

2. **User 1 (Role 1):**
   - Username: `user1`
   - Password: `user123`
   - Email: `user1@passkeysample.local`
   - Role: `role1`

3. **User 2 (Role 2):**
   - Username: `user2`
   - Password: `user123`
   - Email: `user2@passkeysample.local`
   - Role: `role2`

## Modifying the Realm

1. Edit `passkeysample-realm.json`
2. Recreate Keycloak with clean volumes: `docker-compose down -v && docker-compose up -d`
   - **Note:** Simply restarting Keycloak won't update existing users/clients due to `IGNORE_EXISTING` import strategy

**Important:** Keycloak uses `IGNORE_EXISTING` import strategy, meaning existing realms/users won't be overwritten on restart. To apply changes, you must remove volumes and recreate containers.

