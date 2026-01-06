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

export interface WebAuthnRegistrationOptionsResponse {
  options: PublicKeyCredentialCreationOptions
  challengeKey: string
}

export interface WebAuthnRegistrationResponse {
  message: string
  publicKey: string // Base64 encoded public key for client storage
  credentialId: string // Base64 encoded credential ID for client storage
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
  response: AuthenticatorAssertionResponse,
  usernameOrEmail: string
): Promise<WebAuthnVerifyResponse> {
  const webAuthnResponse = convertWebAuthnResponse(credential, response)
  
  // Retrieve public key from local storage
  const storageKey = `webauthn_cred_${usernameOrEmail.toLowerCase()}`
  const storedCredential = localStorage.getItem(storageKey)
  
  if (!storedCredential) {
    throw new Error('Public key not found. Please register your passkey first.')
  }
  
  const credentialData = JSON.parse(storedCredential)
  if (!credentialData.publicKey) {
    throw new Error('Invalid credential data. Please register your passkey again.')
  }

  const verifyResponse = await apiClient.post<WebAuthnVerifyResponse>(
    '/api/auth/webauthn/verify',
    {
      challengeKey,
      response: webAuthnResponse,
      publicKey: credentialData.publicKey,
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

  // Step 3: Verify with backend (pass usernameOrEmail to retrieve public key)
  return verifyWebAuthn(challengeKey, credential, response, usernameOrEmail)
}

/**
 * Converts PublicKeyCredentialCreationOptions challenge from base64url to ArrayBuffer
 */
function convertCreateChallenge(challenge: BufferSource | string): ArrayBuffer {
  if (challenge instanceof ArrayBuffer) {
    return challenge
  }
  if (typeof challenge === 'string') {
    return base64UrlToArrayBuffer(challenge)
  }
  // Handle Uint8Array or other BufferSource types
  if (challenge instanceof Uint8Array) {
    return challenge.buffer.slice(challenge.byteOffset, challenge.byteOffset + challenge.byteLength)
  }
  // Fallback: try to convert as string
  return base64UrlToArrayBuffer(challenge as unknown as string)
}

/**
 * Converts PublicKeyCredentialCreationOptions excludeCredentials from base64url to ArrayBuffer
 */
function convertExcludeCredentials(
  excludeCredentials?: PublicKeyCredentialDescriptor[]
): PublicKeyCredentialDescriptor[] | undefined {
  if (!excludeCredentials) return undefined

  return excludeCredentials.map((cred) => ({
    ...cred,
    id: typeof cred.id === 'string' 
      ? base64UrlToArrayBuffer(cred.id) 
      : cred.id,
  }))
}

/**
 * Converts WebAuthn registration response to format expected by backend
 */
function convertRegistrationResponse(
  credential: PublicKeyCredential,
  response: AuthenticatorAttestationResponse
) {
  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    response: {
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      attestationObject: arrayBufferToBase64Url(response.attestationObject),
    },
    type: credential.type,
  }
}

/**
 * Gets WebAuthn registration options from the backend
 */
export async function getRegistrationOptions(
  usernameOrEmail: string
): Promise<WebAuthnRegistrationOptionsResponse> {
  const response = await apiClient.post<WebAuthnRegistrationOptionsResponse>(
    '/api/auth/webauthn/register/options',
    { usernameOrEmail }
  )
  return response.data
}

/**
 * Registers WebAuthn credential with the backend
 */
export async function registerWebAuthn(
  usernameOrEmail: string,
  challengeKey: string,
  credential: PublicKeyCredential,
  response: AuthenticatorAttestationResponse
): Promise<WebAuthnRegistrationResponse> {
  const registrationResponse = convertRegistrationResponse(credential, response)

  const registerResponse = await apiClient.post<WebAuthnRegistrationResponse>(
    '/api/auth/webauthn/register',
    {
      usernameOrEmail,
      challengeKey,
      response: registrationResponse,
    }
  )

  return registerResponse.data
}

/**
 * Complete WebAuthn registration flow
 */
export async function registerWithWebAuthn(
  usernameOrEmail: string
): Promise<WebAuthnRegistrationResponse> {
  // Step 1: Get WebAuthn registration options from backend
  const { options, challengeKey } = await getRegistrationOptions(usernameOrEmail)

  // Step 2: Perform WebAuthn registration (this creates a new credential)
  // Convert challenge - it might be a string (base64url) or BufferSource
  const challengeValue = options.challenge
  const convertedChallenge = typeof challengeValue === 'string' 
    ? convertCreateChallenge(challengeValue)
    : convertCreateChallenge(challengeValue as BufferSource)

  // Convert user.id from base64url string to ArrayBuffer
  const user = options.user
  let convertedUserId: ArrayBuffer
  if (typeof user.id === 'string') {
    convertedUserId = base64UrlToArrayBuffer(user.id)
  } else if (user.id instanceof ArrayBuffer) {
    convertedUserId = user.id
  } else if (user.id instanceof Uint8Array) {
    convertedUserId = user.id.buffer.slice(user.id.byteOffset, user.id.byteOffset + user.id.byteLength)
  } else {
    // Fallback: try to convert as if it's a typed array
    convertedUserId = new Uint8Array(user.id as unknown as ArrayLike<number>).buffer
  }

  const convertedUser: PublicKeyCredentialUserEntity = {
    ...user,
    id: convertedUserId,
  }

  const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
    challenge: convertedChallenge,
    rp: options.rp,
    user: convertedUser,
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    attestation: options.attestation,
    excludeCredentials: convertExcludeCredentials(options.excludeCredentials),
    authenticatorSelection: options.authenticatorSelection,
    extensions: options.extensions,
  }

  const credential = (await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions,
  })) as PublicKeyCredential | null

  if (!credential) {
    throw new Error('WebAuthn registration was cancelled or failed')
  }

  const response = credential.response as AuthenticatorAttestationResponse

  // Step 3: Register with backend
  const registrationResult = await registerWebAuthn(usernameOrEmail, challengeKey, credential, response)
  
  // Step 4: Store public key and credential ID locally for use during login
  if (registrationResult.publicKey && registrationResult.credentialId) {
    const storageKey = `webauthn_cred_${usernameOrEmail.toLowerCase()}`
    localStorage.setItem(storageKey, JSON.stringify({
      publicKey: registrationResult.publicKey,
      credentialId: registrationResult.credentialId,
      timestamp: Date.now()
    }))
  }
  
  return registrationResult
}

