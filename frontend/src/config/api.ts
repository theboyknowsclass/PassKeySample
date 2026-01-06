import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { generateDPoPProof } from '../services/dpopService'
import { getAccessToken } from '../services/tokenStorage'
import { refreshToken } from '../services/tokenRefreshService'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://localhost:5001'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Track if we're currently refreshing to prevent concurrent refresh attempts
let isRefreshing = false
let failedQueue: Array<{
  resolve: (value?: unknown) => void
  reject: (reason?: unknown) => void
}> = []

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error)
    } else {
      prom.resolve(token)
    }
  })
  failedQueue = []
}

// Request interceptor for adding DPoP proof and auth tokens
apiClient.interceptors.request.use(
  async (config) => {
    // Skip DPoP for auth endpoints (they don't require authentication)
    const url = config.url || ''
    if (
      url.includes('/api/auth/webauthn/options') ||
      url.includes('/api/auth/webauthn/verify') ||
      url.includes('/api/auth/webauthn/register/options') ||
      url.includes('/api/auth/webauthn/register') ||
      url.includes('/api/auth/refresh')
    ) {
      // For refresh endpoint, DPoP is added manually in tokenRefreshService
      if (url.includes('/api/auth/refresh')) {
        return config
      }
      return config
    }

    const accessToken = getAccessToken()
    if (accessToken) {
      // Generate DPoP proof for this request
      const fullUrl = `${config.baseURL || API_BASE_URL}${url}`
      const dpopProof = await generateDPoPProof(
        (config.method || 'GET').toUpperCase(),
        fullUrl,
        accessToken
      )

      // Add DPoP header
      config.headers.DPoP = dpopProof

      // Add Authorization header
      config.headers.Authorization = `Bearer ${accessToken}`
    }

    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling and token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean
    }

    // Handle 401 Unauthorized - token expired
    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      if (isRefreshing) {
        // If refresh is in progress, queue this request
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        })
          .then((token) => {
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${token}`
            }
            return apiClient(originalRequest)
          })
          .catch((err) => {
            return Promise.reject(err)
          })
      }

      originalRequest._retry = true
      isRefreshing = true

      try {
        // Try to refresh token
        const refreshResponse = await refreshToken()
        const newAccessToken = refreshResponse.accessToken

        // Process queued requests
        processQueue(null, newAccessToken)

        // Retry original request with new token
        if (originalRequest.headers) {
          const fullUrl = `${originalRequest.baseURL || API_BASE_URL}${originalRequest.url || ''}`
          const dpopProof = await generateDPoPProof(
            (originalRequest.method || 'GET').toUpperCase(),
            fullUrl,
            newAccessToken
          )
          originalRequest.headers.DPoP = dpopProof
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`
        }

        isRefreshing = false
        return apiClient(originalRequest)
      } catch (refreshError) {
        // Refresh failed - clear tokens and reject
        processQueue(refreshError as Error, null)
        isRefreshing = false
        return Promise.reject(refreshError)
      }
    }

    // For other errors, just reject
    return Promise.reject(error)
  }
)

