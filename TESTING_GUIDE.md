# Testing Guide - Token Exchange & JWT Validation Implementation

This guide covers testing the newly implemented:
- **RFC 8693 Token Exchange** for user token issuance
- **JWT validation using JWKS** from OIDC discovery
- **DPoP validation** with JWT token validation
- **IdP-agnostic configuration**

## Prerequisites

1. **Ensure certificates are set up:**
   ```powershell
   # Windows
   .\setup-all-certs.ps1
   .\scripts\trust-ca.ps1  # Run as Administrator

   # Linux/Mac
   ./setup-all-certs.sh
   ./scripts/trust-ca.sh
   ```

2. **Start services:**
   ```bash
   docker-compose up --build
   ```

3. **Verify Keycloak is running:**
   - Check: http://localhost:8080
   - Admin console: http://localhost:8080 (admin/admin123)

## Testing Strategy

### 1. End-to-End Testing (Full Flow)

#### Test 1.1: Complete WebAuthn Authentication Flow

**Steps:**
1. Navigate to frontend: https://localhost:3000/login
2. Enter username: `user1` or `user1@passkeysample.local`
3. Click "Sign In" and complete WebAuthn challenge
4. Verify you receive tokens and are authenticated

**Expected Results:**
- ✅ WebAuthn challenge succeeds
- ✅ Token Exchange is called successfully
- ✅ Access token and refresh token are returned
- ✅ User can make authenticated API calls with DPoP

**What to Check in Logs:**
```
[Information] Generated WebAuthn options for: user1
[Information] WebAuthn verification successful for user: user1@passkeysample.local
[Information] Successfully exchanged service token for user token via Token Exchange
[Information] JWT token validated successfully. Subject: ..., Issuer: ...
[Information] DPoP proof validated successfully
```

#### Test 1.2: Authenticated API Request with DPoP

**Steps:**
1. After successful login, make an API request (e.g., to `/api/version`)
2. Include `Authorization: Bearer <token>` header
3. Include `DPoP: <dpop-proof>` header

**Expected Results:**
- ✅ JWT token is validated first (signature, expiration, issuer)
- ✅ DPoP proof is validated (bound to token)
- ✅ Request succeeds with 200 OK

**What to Check in Logs:**
```
[Information] JWT token validated successfully. Subject: ..., Issuer: ...
[Information] DPoP proof validated successfully
```

---

### 2. Component-Level Testing

#### Test 2.1: OIDC Discovery Service

**Test via API:**
```bash
curl -k https://localhost:5001/api/identityprovider/discovery
```

**Expected Results:**
- ✅ Returns discovery document with `token_endpoint`, `jwks_uri`, `issuer`
- ✅ All endpoints are properly formatted

#### Test 2.2: Token Exchange Service

**Check logs during login for:**
- Service account token acquisition
- Token exchange request
- User token received

**What to Check:**
- Log message: `"Successfully exchanged service token for user token via Token Exchange"`
- OR if fallback: `"Token Exchange failed... Falling back to service account token"`

**Note:** Keycloak may not fully support RFC 8693 Token Exchange in dev mode. You might see fallback behavior.

#### Test 2.3: JWT Token Validation

**Manually test with a token:**
1. Get a token from login
2. Decode it at https://jwt.io
3. Verify claims: `iss`, `aud`, `exp`, `sub`

**Test invalid token scenarios:**

```bash
# Expired token
curl -k -X GET https://localhost:5001/api/version \
  -H "Authorization: Bearer <expired-token>" \
  -H "DPoP: <proof>"

# Invalid signature token (modify token)
curl -k -X GET https://localhost:5001/api/version \
  -H "Authorization: Bearer <modified-token>" \
  -H "DPoP: <proof>"

# Missing DPoP header
curl -k -X GET https://localhost:5001/api/version \
  -H "Authorization: Bearer <valid-token>"
```

**Expected Results:**
- ❌ Expired token → `401 Unauthorized` with "Token has expired"
- ❌ Invalid signature → `401 Unauthorized` with "Invalid token signature"
- ❌ Missing DPoP → `401 Unauthorized` with "Missing DPoP header"

#### Test 2.4: DPoP Validation

**Test DPoP-specific failures:**

```bash
# Wrong HTTP method in DPoP proof
# (Modify proof to have htm=POST when making GET request)

# Wrong URL in DPoP proof
# (Modify proof to have different htu)

# Reused DPoP proof (replay attack)
# (Reuse same DPoP proof twice)
```

**Expected Results:**
- ❌ Wrong method → `401 Unauthorized` with "HTTP method mismatch"
- ❌ Wrong URL → `401 Unauthorized` with "HTTP URL mismatch"
- ❌ Reused proof → `401 Unauthorized` with "replay attack detected"

---

### 3. Configuration Testing

#### Test 3.1: Verify OIDC Discovery Endpoint Configuration

**Check appsettings.json:**
```json
{
  "IdentityProvider": {
    "OidcDiscoveryEndpoint": "/realms/passkeysample/.well-known/openid-configuration"
  }
}
```

**Verify it resolves correctly:**
```bash
curl -k https://localhost:8443/realms/passkeysample/.well-known/openid-configuration
```

**Expected:** Full OIDC discovery document with `jwks_uri` and `token_endpoint`

#### Test 3.2: Test Standard OIDC Endpoint (ADFS-style)

**Temporarily update appsettings.json:**
```json
{
  "IdentityProvider": {
    "BaseUrl": "localhost",
    "OidcDiscoveryEndpoint": "/.well-known/openid-configuration"
  }
}
```

**Expected:** Should still work if Keycloak exposes standard endpoint (may not in dev mode)

---

### 4. Error Handling & Edge Cases

#### Test 4.1: Keycloak Unavailable

**Steps:**
1. Stop Keycloak: `docker-compose stop keycloak`
2. Attempt login

**Expected:**
- ✅ Graceful error handling
- ✅ Clear error message about IdP unavailability
- ✅ No unhandled exceptions

#### Test 4.2: Invalid Discovery Document

**Steps:**
1. Temporarily break discovery endpoint
2. Attempt operations that require discovery

**Expected:**
- ✅ Service fails gracefully
- ✅ Error logged clearly
- ✅ User-friendly error response

#### Test 4.3: JWKS Unavailable

**Steps:**
1. If possible, block JWKS endpoint
2. Attempt token validation

**Expected:**
- ✅ Error logged
- ✅ Clear error about JWKS retrieval failure

---

### 5. Log Verification Checklist

Monitor logs for these key messages:

**✅ Success Indicators:**
- `"Successfully fetched OIDC discovery document"`
- `"Initialized OIDC configuration manager with JWKS URI: ..."`
- `"Successfully exchanged service token for user token via Token Exchange"`
- `"JWT token validated successfully. Subject: ..., Issuer: ..."`
- `"DPoP proof validated successfully"`

**⚠️ Warning Indicators (may be expected):**
- `"Token Exchange (RFC 8693) failed"` - Keycloak may not support this fully
- `"Falling back to service account token"` - Expected if Token Exchange fails

**❌ Error Indicators (investigate):**
- `"Failed to initialize OIDC configuration"`
- `"OIDC discovery document is null or JWKS URI is missing"`
- `"JWT token signature is invalid"`
- `"Token validation failed"`

---

### 6. Integration with Frontend

#### Test 6.1: Full Frontend Flow

1. Open browser dev tools (Network tab)
2. Navigate to https://localhost:3000/login
3. Complete login
4. Verify:
   - ✅ Token stored in localStorage/sessionStorage
   - ✅ DPoP proofs generated for subsequent requests
   - ✅ API calls include both `Authorization` and `DPoP` headers
   - ✅ Requests succeed

#### Test 6.2: Token Refresh

1. Wait for token to expire (or manually expire it)
2. Make an API request
3. Verify:
   - ✅ Token refresh is attempted automatically
   - ✅ New tokens are stored
   - ✅ Request retried with new token

---

### 7. Keycloak-Specific Token Exchange Testing

**Note:** Keycloak's Token Exchange support varies by version and configuration.

**Check if Token Exchange is enabled:**
1. Login to Keycloak Admin Console
2. Go to Realm Settings → Token Exchange
3. Verify settings

**Alternative:** Test with service account token (fallback):
- Should still work, but token won't be user-specific
- Check logs for fallback message

---

### 8. Testing IdP-Agnostic Behavior

#### Test 8.1: Verify No Hardcoded Paths

**Search codebase for hardcoded paths:**
```bash
# Should NOT find these:
grep -r "realms/passkeysample" PassKeySample.Api/
grep -r "/protocol/openid-connect" PassKeySample.Api/
```

**Expected:** Only in configuration files and comments

#### Test 8.2: Configuration Flexibility

**Test different discovery endpoints:**
- Keycloak realm path (current): `/realms/passkeysample/.well-known/openid-configuration`
- Standard OIDC path: `/.well-known/openid-configuration`
- Custom path: `/{custom}/.well-known/openid-configuration`

**Expected:** All should work if discovery document is valid

---

## Troubleshooting

### Issue: Token Exchange Fails

**Symptoms:**
- Logs show: `"Token Exchange (RFC 8693) failed"`
- Fallback to service account token

**Possible Causes:**
1. Keycloak doesn't support Token Exchange in dev mode
2. Token Exchange not enabled in Keycloak
3. Wrong subject_token_type format

**Solutions:**
1. Check Keycloak version and configuration
2. Verify Token Exchange is enabled in realm settings
3. Service account token fallback should still work for basic testing

### Issue: JWT Validation Fails

**Symptoms:**
- `"JWT token signature is invalid"`
- `"Invalid token issuer"`

**Possible Causes:**
1. JWKS not retrieved correctly
2. Token from different issuer
3. Clock skew issues

**Solutions:**
1. Check JWKS URI in discovery document
2. Verify issuer in token matches configuration
3. Check system clock synchronization

### Issue: DPoP Validation Fails

**Symptoms:**
- `"HTTP method mismatch"`
- `"HTTP URL mismatch"`
- `"Access token hash mismatch"`

**Possible Causes:**
1. Frontend generating incorrect DPoP proof
2. URL normalization differences
3. Token changed between proof generation and validation

**Solutions:**
1. Check frontend DPoP service
2. Verify URL normalization logic matches
3. Ensure same token used for proof and validation

---

## Quick Test Script

Save this as `test-api.ps1` (PowerShell) or `test-api.sh` (Bash):

```bash
#!/bin/bash

# Get token from login (you'll need to replace this with actual token from frontend)
TOKEN="<your-access-token>"
DPOP_PROOF="<your-dpop-proof>"

# Test authenticated endpoint
curl -k -X GET https://localhost:5001/api/version \
  -H "Authorization: Bearer $TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -v

# Expected: 200 OK with version info
```

---

## Success Criteria

✅ **All tests pass:**
- WebAuthn authentication works end-to-end
- Token Exchange succeeds (or gracefully falls back)
- JWT tokens are validated correctly
- DPoP proofs are validated correctly
- Invalid tokens/proofs are rejected
- Configuration is IdP-agnostic
- No hardcoded Keycloak paths in code

✅ **Logs show:**
- Successful OIDC discovery
- JWKS retrieval and caching
- Token validation success
- DPoP validation success

✅ **Error handling:**
- Graceful failures
- Clear error messages
- No unhandled exceptions

