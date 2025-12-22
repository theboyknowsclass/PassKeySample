import { SignJWT, importJWK, generateKeyPair } from 'jose'

interface DPoPKeyPair {
  privateKey: CryptoKey
  publicKey: CryptoKey
  publicKeyJwk: JsonWebKey
}

// Store DPoP key pair in closure to minimize exposure
let dpopKeyPair: DPoPKeyPair | null = null

/**
 * Generates a DPoP key pair using Web Crypto API
 */
async function generateDPoPKeyPair(): Promise<DPoPKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', {
    extractable: true,
  })

  // Export public key as JWK for inclusion in DPoP proof
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', publicKey)

  return {
    privateKey,
    publicKey,
    publicKeyJwk: publicKeyJwk as JsonWebKey,
  }
}

/**
 * Gets or generates DPoP key pair (singleton per session)
 */
async function getDPoPKeyPair(): Promise<DPoPKeyPair> {
  if (!dpopKeyPair) {
    dpopKeyPair = await generateDPoPKeyPair()
  }
  return dpopKeyPair
}

/**
 * Computes SHA-256 hash of access token for ath claim
 */
async function computeAccessTokenHash(accessToken: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(accessToken)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = new Uint8Array(hashBuffer)
  
  // Convert to base64url
  let binary = ''
  for (let i = 0; i < hashArray.length; i++) {
    binary += String.fromCharCode(hashArray[i])
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Generates a unique JTI (JWT ID) for DPoP proof
 */
function generateJti(): string {
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Normalizes URL for htu claim (removes trailing slash, query params, fragments)
 */
function normalizeUrl(url: string): string {
  try {
    const urlObj = new URL(url)
    // Remove trailing slash from pathname
    const pathname = urlObj.pathname.replace(/\/$/, '')
    return `${urlObj.protocol}//${urlObj.host}${pathname}`
  } catch {
    // If URL parsing fails, return as-is
    return url.replace(/\/$/, '')
  }
}

/**
 * Generates a DPoP proof JWT
 * @param httpMethod HTTP method (GET, POST, etc.)
 * @param httpUrl Full HTTP URL
 * @param accessToken Access token (for ath claim)
 * @returns DPoP proof JWT string
 */
export async function generateDPoPProof(
  httpMethod: string,
  httpUrl: string,
  accessToken?: string
): Promise<string> {
  const keyPair = await getDPoPKeyPair()
  const now = Math.floor(Date.now() / 1000)
  const jti = generateJti()
  const normalizedUrl = normalizeUrl(httpUrl)

  // Build DPoP proof claims
  const claims: Record<string, unknown> = {
    iat: now,
    jti,
    htm: httpMethod.toUpperCase(),
    htu: normalizedUrl,
  }

  // Add ath claim if access token is provided
  if (accessToken) {
    const ath = await computeAccessTokenHash(accessToken)
    claims.ath = ath
  }

  // Import private key for signing
  const privateKey = await importJWK(
    await crypto.subtle.exportKey('jwk', keyPair.privateKey),
    'ES256'
  )

  // Create and sign JWT
  const jwt = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: keyPair.publicKeyJwk })
    .sign(privateKey)

  return jwt
}

/**
 * Clears the DPoP key pair (call on logout)
 */
export function clearDPoPKeyPair(): void {
  dpopKeyPair = null
}

