import { useAuth } from '../hooks/useAuth'
import { useNavigate } from 'react-router-dom'
import { useQuery } from 'react-query'
import { apiClient } from '../config/api'
import { getJwtClaims, getAccessToken } from '../services/tokenStorage'
import './DashboardPage.css'

interface VersionResponse {
  version: string
  dpopValidated?: boolean
  message?: string
}

function DashboardPage() {
  const { isAuthenticated, logout } = useAuth()
  const navigate = useNavigate()

  // React Query for Role1 endpoint
  const {
    data: role1Data,
    isLoading: isLoadingRole1,
    error: role1Error,
    refetch: fetchRole1,
    isFetching: isFetchingRole1,
  } = useQuery<VersionResponse, Error>({
    queryKey: ['role1-version'],
    queryFn: async () => {
      const response = await apiClient.get<VersionResponse>('/api/role1version')
      
      const dpopValidated = response.headers['x-dpop-validated'] === 'true'
      
      return {
        ...response.data,
        dpopValidated
      }
    },
    enabled: false,
    retry: false,
  })

  // React Query for Role2 endpoint
  const {
    data: role2Data,
    isLoading: isLoadingRole2,
    error: role2Error,
    refetch: fetchRole2,
    isFetching: isFetchingRole2,
  } = useQuery<VersionResponse, Error>({
    queryKey: ['role2-version'],
    queryFn: async () => {
      const response = await apiClient.get<VersionResponse>('/api/role2version')
      
      const dpopValidated = response.headers['x-dpop-validated'] === 'true'
      
      return {
        ...response.data,
        dpopValidated
      }
    },
    enabled: false,
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

  // Decode JWT locally for display
  const accessToken = getAccessToken()
  const jwtClaims = accessToken ? getJwtClaims() : null
  const authenticatedUser = jwtClaims?.preferred_username || jwtClaims?.sub || null
  const tokenIssuer = jwtClaims?.iss || null
  const tokenExpiresAt = jwtClaims?.exp ? new Date(jwtClaims.exp * 1000) : null

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
            <h2>Test Protected Endpoints</h2>
            
            <div className="button-group">
              {/* Role1 Endpoint */}
              <div style={{ marginBottom: '20px' }}>
                <button
                  onClick={() => fetchRole1()}
                  disabled={isFetchingRole1 || isLoadingRole1}
                  className="test-button"
                >
                  {isFetchingRole1 || isLoadingRole1
                    ? 'Loading...'
                    : 'Role 1 Version'}
                </button>

                {role1Data && (
                  <div className="version-result">
                    <div className="result-box">
                      <p>
                        <strong>Version:</strong> {role1Data.version}
                      </p>
                      {role1Data.message && (
                        <p>
                          <strong>Message:</strong> {role1Data.message}
                        </p>
                      )}
                      <p>
                        <strong>DPoP Validated:</strong>{' '}
                        {role1Data.dpopValidated ? '✓ Yes' : '✗ No'}
                      </p>
                    </div>
                  </div>
                )}

                {role1Error && (
                  <div className="error-box">
                    <strong>Error:</strong>{' '}
                    {role1Error instanceof Error
                      ? role1Error.message
                      : String(role1Error)}
                  </div>
                )}
              </div>

              {/* Role2 Endpoint */}
              <div style={{ marginBottom: '20px' }}>
                <button
                  onClick={() => fetchRole2()}
                  disabled={isFetchingRole2 || isLoadingRole2}
                  className="test-button"
                >
                  {isFetchingRole2 || isLoadingRole2
                    ? 'Loading...'
                    : 'Role 2 Version'}
                </button>

                {role2Data && (
                  <div className="version-result">
                    <div className="result-box">
                      <p>
                        <strong>Version:</strong> {role2Data.version}
                      </p>
                      {role2Data.message && (
                        <p>
                          <strong>Message:</strong> {role2Data.message}
                        </p>
                      )}
                      <p>
                        <strong>DPoP Validated:</strong>{' '}
                        {role2Data.dpopValidated ? '✓ Yes' : '✗ No'}
                      </p>
                    </div>
                  </div>
                )}

                {role2Error && (
                  <div className="error-box">
                    <strong>Error:</strong>{' '}
                    {role2Error instanceof Error
                      ? role2Error.message
                      : String(role2Error)}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Display JWT info decoded locally */}
          {jwtClaims && (
            <div className="info-section">
              <h2>Token Information</h2>
              <div className="result-box">
                {authenticatedUser && (
                  <p>
                    <strong>User:</strong> {authenticatedUser}
                  </p>
                )}
                {tokenIssuer && (
                  <p>
                    <strong>Issuer:</strong> {tokenIssuer}
                  </p>
                )}
                {tokenExpiresAt && (
                  <p>
                    <strong>Expires:</strong> {tokenExpiresAt.toLocaleString()}
                  </p>
                )}
                <details className="claims-details">
                  <summary>JWT Claims</summary>
                  <pre className="claims-json">
                    {JSON.stringify(jwtClaims, null, 2)}
                  </pre>
                </details>
              </div>
            </div>
          )}
        </div>

        <button onClick={handleLogout} className="logout-button">
          Sign Out
        </button>
      </div>
    </div>
  )
}

export default DashboardPage

