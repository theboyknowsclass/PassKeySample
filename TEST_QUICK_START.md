# Quick Testing Guide

## 1. Start Services

```bash
docker-compose up --build
```

Wait for all services to start (especially Keycloak health check).

## 2. Test End-to-End Flow

### Option A: Frontend Testing (Recommended)

1. Open https://localhost:3000/login
2. Enter username: `user1`
3. Complete WebAuthn authentication
4. Check browser console and network tab for:
   - ✅ Token received
   - ✅ API calls include `Authorization` and `DPoP` headers
   - ✅ Requests succeed

### Option B: API Testing with Swagger

1. Open https://localhost:5001/swagger
2. Test endpoints that require authentication
3. Use token from frontend login

## 3. Verify in Logs

**Check API logs for:**
```bash
docker-compose logs -f api
```

**Look for:**
- ✅ `"Successfully fetched OIDC discovery document"`
- ✅ `"Initialized OIDC configuration manager with JWKS URI"`
- ✅ `"JWT token validated successfully"`
- ✅ `"DPoP proof validated successfully"`

## 4. Test Error Cases

### Invalid Token
```bash
curl -k -X GET https://localhost:5001/api/version \
  -H "Authorization: Bearer invalid-token" \
  -H "DPoP: invalid-proof"
```

**Expected:** `401 Unauthorized`

### Missing DPoP
```bash
curl -k -X GET https://localhost:5001/api/version \
  -H "Authorization: Bearer <valid-token>"
```

**Expected:** `401 Unauthorized` with "Missing DPoP header"

## 5. Verify Token Exchange

**In API logs, look for:**
- `"Successfully exchanged service token for user token via Token Exchange"`

**OR if Token Exchange not supported:**
- `"Token Exchange (RFC 8693) failed"`
- `"Falling back to service account token"`

*(Keycloak may not fully support Token Exchange in dev mode - this is OK)*

## Common Issues

**Issue:** Token validation fails
- **Check:** JWKS URI in discovery document
- **Verify:** Keycloak is accessible and certificates trusted

**Issue:** Token Exchange always fails
- **Check:** Keycloak Token Exchange settings
- **Note:** Fallback to service token is acceptable for testing

**Issue:** DPoP validation fails
- **Check:** Frontend is generating DPoP proofs correctly
- **Verify:** Same token used in Authorization header and DPoP proof

