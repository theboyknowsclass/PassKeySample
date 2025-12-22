import { apiClient } from '../config/api'
import { generateDPoPProof } from './dpopService'
import {
  getAccessToken,
  getRefreshToken,
  updateAccessToken,
  isAccessTokenExpired,
} from './tokenStorage'

interface RefreshTokenResponse {
  accessToken: string
  refreshToken?: string
  expiresIn: number
  tokenType: string
}

// Track if refresh is in progress to prevent concurrent refresh attempts
let refreshPromise: Promise<RefreshTokenResponse> | null = null

/**
 * Refreshes the access token using the refresh token
 */
async function performTokenRefresh(): Promise<RefreshTokenResponse> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) {
    throw new Error('No refresh token available')
  }

  const currentAccessToken = getAccessToken() ?? ''

  // Generate DPoP proof for refresh request
  const refreshUrl = `${apiClient.defaults.baseURL}/api/auth/refresh`
  const dpopProof = await generateDPoPProof('POST', refreshUrl, currentAccessToken)

  // Call refresh endpoint
  const response = await apiClient.post<RefreshTokenResponse>(
    '/api/auth/refresh',
    { refreshToken },
    {
      headers: {
        DPoP: dpopProof,
        ...(currentAccessToken ? { Authorization: `Bearer ${currentAccessToken}` } : {}),
      },
    }
  )

  return response.data
}

/**
 * Refreshes the access token, preventing concurrent refresh attempts
 */
export async function refreshToken(): Promise<RefreshTokenResponse> {
  // If refresh is already in progress, return the existing promise
  if (refreshPromise) {
    return refreshPromise
  }

  // Start refresh
  refreshPromise = performTokenRefresh()
    .then((response) => {
      // Update stored tokens
      updateAccessToken(
        response.accessToken,
        response.expiresIn,
        response.refreshToken
      )
      return response
    })
    .finally(() => {
      // Clear refresh promise when done
      refreshPromise = null
    })

  return refreshPromise
}

/**
 * Checks if token needs refresh and refreshes if necessary
 */
export async function ensureValidToken(): Promise<string | null> {
  const accessToken = getAccessToken()

  // If token exists and is not expired, return it
  if (accessToken && !isAccessTokenExpired()) {
    return accessToken
  }

  // If token is expired or missing, try to refresh
  if (getRefreshToken()) {
    try {
      const refreshResponse = await refreshToken()
      return refreshResponse.accessToken
    } catch (error) {
      console.error('Token refresh failed:', error)
      return null
    }
  }

  // No refresh token available
  return null
}

/**
 * Clears refresh state (call on logout)
 */
export function clearRefreshState(): void {
  refreshPromise = null
}

