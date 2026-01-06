import { useState, useCallback } from 'react'
import { registerWithWebAuthn } from '../services/webauthnService'

export function usePasskeyRegistration() {
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isSuccess, setIsSuccess] = useState(false)

  const register = useCallback(async (usernameOrEmail: string) => {
    setIsLoading(true)
    setError(null)
    setIsSuccess(false)

    try {
      // Check if WebAuthn is supported
      if (!window.PublicKeyCredential) {
        throw new Error('WebAuthn is not supported in this browser')
      }

      // Perform WebAuthn registration
      await registerWithWebAuthn(usernameOrEmail)

      setIsSuccess(true)
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Registration failed'
      setError(errorMessage)
      setIsSuccess(false)
      throw err
    } finally {
      setIsLoading(false)
    }
  }, [])

  const reset = useCallback(() => {
    setError(null)
    setIsSuccess(false)
  }, [])

  return {
    register,
    isLoading,
    error,
    isSuccess,
    reset,
  }
}

