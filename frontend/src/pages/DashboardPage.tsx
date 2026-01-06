import { useAuth } from '../hooks/useAuth'
import { useNavigate } from 'react-router-dom'
import { useQuery } from 'react-query'
import { apiClient } from '../config/api'
import './DashboardPage.css'

interface VersionResponse {
  version: string
  authenticatedUser?: string
  tokenIssuer?: string
  tokenExpiresAt?: string
  dpopValidated: boolean
  userClaims?: Record<string, unknown>
}

function DashboardPage() {
  const { isAuthenticated, logout } = useAuth()
  const navigate = useNavigate()

  // React Query to fetch version from protected endpoint
  const {
    data: versionData,
    isLoading: isLoadingVersion,
    error: versionError,
    refetch: fetchVersion,
    isFetching: isFetchingVersion,
  } = useQuery<VersionResponse>({
    queryKey: ['version'],
    queryFn: async () => {
      const response = await apiClient.get<VersionResponse>('/api/version')
      return response.data
    },
    enabled: false, // Don't fetch automatically, only on button click
    retry: false,
  })

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  if (!isAuthenticated) {
    navigate('/login')
    return null
  }

  // Extract error message for display
  const errorMessage = versionError
    ? versionError instanceof Error
      ? versionError.message
      : typeof versionError === 'string'
      ? versionError
      : 'Failed to fetch version'
    : null

  return (
    <div className="dashboard-container">
      <div className="dashboard-card">
        <h1 className="dashboard-title">Welcome!</h1>
        <p className="dashboard-subtitle">
          You have successfully authenticated with your passkey.
        </p>
        
        <div className="dashboard-info">
          <div className="info-section">
            <h2>Authentication Status</h2>
            <p className="status-success">✓ Authenticated</p>
          </div>

          <div className="info-section">
            <h2>What's Next?</h2>
            <ul className="feature-list">
              <li>Your access token is stored securely</li>
              <li>DPoP proofs are generated for API requests</li>
              <li>Token refresh is handled automatically</li>
            </ul>
          </div>

          <div className="info-section">
            <h2>Test Protected Endpoint</h2>
            <button
              onClick={() => fetchVersion()}
              disabled={isFetchingVersion || isLoadingVersion}
              className="test-button"
            >
              {isFetchingVersion || isLoadingVersion
                ? 'Loading...'
                : 'Get API Version (Protected)'}
            </button>

            {versionData && (
              <div className="version-result">
                <h3>Response:</h3>
                <div className="result-box">
                  <p>
                    <strong>Version:</strong> {versionData.version}
                  </p>
                  {versionData.authenticatedUser && (
                    <p>
                      <strong>User:</strong> {versionData.authenticatedUser}
                    </p>
                  )}
                  {versionData.tokenIssuer && (
                    <p>
                      <strong>Issuer:</strong> {versionData.tokenIssuer}
                    </p>
                  )}
                  {versionData.tokenExpiresAt && (
                    <p>
                      <strong>Expires:</strong>{' '}
                      {new Date(versionData.tokenExpiresAt).toLocaleString()}
                    </p>
                  )}
                  <p>
                    <strong>DPoP Validated:</strong>{' '}
                    {versionData.dpopValidated ? '✓ Yes' : '✗ No'}
                  </p>
                  {versionData.userClaims && (
                    <details className="claims-details">
                      <summary>User Claims</summary>
                      <pre className="claims-json">
                        {JSON.stringify(versionData.userClaims, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              </div>
            )}

            {errorMessage && (
              <div className="error-box">
                <strong>Error:</strong> {errorMessage}
              </div>
            )}
          </div>
        </div>

        <button onClick={handleLogout} className="logout-button">
          Sign Out
        </button>
      </div>
    </div>
  )
}

export default DashboardPage

