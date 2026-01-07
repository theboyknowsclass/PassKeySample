interface TokenData {
  accessToken: string
  refreshToken?: string
  expiresAt: number // Unix timestamp in milliseconds
}

// Store tokens in closure to minimize exposure
let tokenData: TokenData | null = null

/**
 * Stores authentication tokens in memory
 */
export function setTokens(
  accessToken: string,
  refreshToken: string | undefined,
  expiresIn: number
): void {
  const expiresAt = Date.now() + expiresIn * 1000
  tokenData = {
    accessToken,
    refreshToken,
    expiresAt,
  }
}

/**
 * Gets the access token
 */
export function getAccessToken(): string | null {
  if (!tokenData) return null
  
  // Check if token is expired
  if (Date.now() >= tokenData.expiresAt) {
    return null
  }
  
  return tokenData.accessToken
}

/**
 * Gets the refresh token
 */
export function getRefreshToken(): string | null {
  return tokenData?.refreshToken ?? null
}

/**
 * Checks if access token is expired or will expire soon
 * @param bufferSeconds Number of seconds before expiration to consider token expired (default: 60)
 */
export function isAccessTokenExpired(bufferSeconds: number = 60): boolean {
  if (!tokenData) return true
  
  const bufferMs = bufferSeconds * 1000
  return Date.now() >= (tokenData.expiresAt - bufferMs)
}

/**
 * Checks if user is authenticated (has valid tokens)
 */
export function isAuthenticated(): boolean {
  return getAccessToken() !== null
}

/**
 * Clears all stored tokens (call on logout)
 */
export function clearTokens(): void {
  tokenData = null
}

/**
 * Updates the access token (used during refresh)
 */
export function updateAccessToken(
  accessToken: string,
  expiresIn: number,
  refreshToken?: string
): void {
  if (!tokenData) {
    setTokens(accessToken, refreshToken, expiresIn)
    return
  }
  
  const expiresAt = Date.now() + expiresIn * 1000
  tokenData = {
    accessToken,
    refreshToken: refreshToken ?? tokenData.refreshToken,
    expiresAt,
  }
}

/**
 * Decodes a JWT token and returns its payload
 */
export function decodeJwt(token: string): any {
  try {
    const base64Url = token.split('.')[1]
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return JSON.parse(jsonPayload)
  } catch {
    return null
  }
}

/**
 * Gets the JWT claims from the current access token
 */
export function getJwtClaims(): Record<string, any> | null {
  const token = getAccessToken()
  if (!token) return null
  return decodeJwt(token)
}

