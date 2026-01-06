import { useState, useCallback, useEffect } from 'react'
import { authenticateWithWebAuthn } from '../services/webauthnService'
import {
  setTokens,
  clearTokens,
  isAuthenticated,
  getAccessToken,
} from '../services/tokenStorage'
import { clearDPoPKeyPair } from '../services/dpopService'
import { clearRefreshState } from '../services/tokenRefreshService'

export function useAuth() {
  const [isAuth, setIsAuth] = useState(isAuthenticated())
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Check authentication status on mount and when tokens change
  useEffect(() => {
    const checkAuth = () => {
      setIsAuth(isAuthenticated())
    }

    // Check immediately
    checkAuth()

    // Check periodically (every 5 seconds) to catch token expiration
    const interval = setInterval(checkAuth, 5000)

    return () => clearInterval(interval)
  }, [])

  const login = useCallback(async (usernameOrEmail: string) => {
    setIsLoading(true)
    setError(null)

    try {
      // Check if WebAuthn is supported
      if (!window.PublicKeyCredential) {
        throw new Error('WebAuthn is not supported in this browser')
      }

      // Perform WebAuthn authentication
      const response = await authenticateWithWebAuthn(usernameOrEmail)

      // Store tokens
      setTokens(
        response.accessToken,
        response.refreshToken,
        response.expiresIn
      )

      setIsAuth(true)
      return response
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Authentication failed'
      setError(errorMessage)
      setIsAuth(false)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  const logout = useCallback(() => {
    clearTokens()
    clearDPoPKeyPair()
    clearRefreshState()
    setIsAuth(false)
    setError(null)
  }, [])

  const getToken = useCallback(() => {
    return getAccessToken()
  }, [])

  return {
    isAuthenticated: isAuth,
    isLoading,
    error,
    login,
    logout,
    getToken,
  } as const
}

