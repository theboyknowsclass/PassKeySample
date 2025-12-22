import { apiClient } from '../config/api'

export interface WebAuthnOptionsResponse {
  options: PublicKeyCredentialRequestOptions
  challengeKey: string
}

export interface WebAuthnVerifyResponse {
  accessToken: string
  refreshToken?: string
  expiresIn: number
  tokenType: string
}

export interface WebAuthnOptionsRequest {
  usernameOrEmail: string
}

/**
 * Converts ArrayBuffer to base64url string
 */
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Converts base64url string to ArrayBuffer
 */
function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

/**
 * Converts PublicKeyCredentialRequestOptions challenge from base64url to ArrayBuffer
 */
function convertChallenge(challenge: string): ArrayBuffer {
  return base64UrlToArrayBuffer(challenge)
}

/**
 * Converts PublicKeyCredentialRequestOptions allowCredentials from base64url to ArrayBuffer
 */
function convertAllowCredentials(
  allowCredentials?: PublicKeyCredentialDescriptor[]
): PublicKeyCredentialDescriptor[] | undefined {
  if (!allowCredentials) return undefined

  return allowCredentials.map((cred) => ({
    ...cred,
    id: typeof cred.id === 'string' 
      ? base64UrlToArrayBuffer(cred.id) 
      : cred.id,
  }))
}

/**
 * Gets WebAuthn options from the backend
 */
export async function getWebAuthnOptions(
  usernameOrEmail: string
): Promise<WebAuthnOptionsResponse> {
  const response = await apiClient.post<WebAuthnOptionsResponse>(
    '/api/auth/webauthn/options',
    { usernameOrEmail }
  )
  return response.data
}


/**
 * Converts WebAuthn response to format expected by backend
 */
function convertWebAuthnResponse(
  credential: PublicKeyCredential,
  response: AuthenticatorAssertionResponse
) {
  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    response: {
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
      signature: arrayBufferToBase64Url(response.signature),
      userHandle: response.userHandle
        ? arrayBufferToBase64Url(response.userHandle)
        : null,
    },
    type: credential.type,
  }
}

/**
 * Verifies WebAuthn authentication with the backend
 */
export async function verifyWebAuthn(
  challengeKey: string,
  credential: PublicKeyCredential,
  response: AuthenticatorAssertionResponse
): Promise<WebAuthnVerifyResponse> {
  const webAuthnResponse = convertWebAuthnResponse(credential, response)

  const verifyResponse = await apiClient.post<WebAuthnVerifyResponse>(
    '/api/auth/webauthn/verify',
    {
      challengeKey,
      response: webAuthnResponse,
    }
  )

  return verifyResponse.data
}

/**
 * Complete WebAuthn authentication flow
 */
export async function authenticateWithWebAuthn(
  usernameOrEmail: string
): Promise<WebAuthnVerifyResponse> {
  // Step 1: Get WebAuthn options from backend
  const { options, challengeKey } = await getWebAuthnOptions(usernameOrEmail)

  // Step 2: Perform WebAuthn authentication (this returns both credential and response)
  const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
    challenge: convertChallenge(
      typeof options.challenge === 'string' 
        ? options.challenge 
        : (options.challenge as unknown as string)
    ),
    allowCredentials: convertAllowCredentials(options.allowCredentials),
    userVerification: options.userVerification,
    timeout: options.timeout,
    rpId: options.rpId,
  }

  const credential = (await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null

  if (!credential) {
    throw new Error('WebAuthn authentication was cancelled or failed')
  }

  const response = credential.response as AuthenticatorAssertionResponse

  // Step 3: Verify with backend
  return verifyWebAuthn(challengeKey, credential, response)
}

