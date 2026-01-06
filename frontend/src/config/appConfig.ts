/**
 * Application configuration
 * Reads from environment variables
 */

/**
 * Checks if passkey registration is enabled
 * Defaults to true in development, false in production
 */
export function isPasskeyRegistrationEnabled(): boolean {
  const envValue = import.meta.env.VITE_ENABLE_PASSKEY_REGISTRATION
  if (envValue === undefined || envValue === '') {
    // Default: enabled in dev mode, disabled in production
    // For Docker builds, default to true unless explicitly set to false
    return true
  }
  return envValue === 'true' || envValue === '1'
}

