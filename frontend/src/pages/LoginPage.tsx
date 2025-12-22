import { useForm } from 'react-hook-form'
import { useAuth } from '../hooks/useAuth'
import './LoginPage.css'

interface LoginFormData {
  usernameOrEmail: string
}

function LoginPage() {
  const { login, isLoading, error } = useAuth()
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<LoginFormData>({
    mode: 'onBlur',
  })

  const onSubmit = async (data: LoginFormData) => {
    try {
      await login(data.usernameOrEmail)
      // Login successful - tokens are stored, user is authenticated
      // You can redirect or show success message here
      console.log('Login successful')
    } catch (err) {
      // Error is handled by useAuth hook, but we can also set form error
      const errorMessage =
        err instanceof Error ? err.message : 'Authentication failed'
      setError('usernameOrEmail', {
        type: 'manual',
        message: errorMessage,
      })
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <h1 className="login-title">PassKey Sample</h1>
        <p className="login-subtitle">Sign in to your account</p>

        <form onSubmit={handleSubmit(onSubmit)} className="login-form">
          <div className="form-group">
            <label htmlFor="usernameOrEmail" className="form-label">
              Username or Email
            </label>
            <input
              id="usernameOrEmail"
              type="text"
              className={`form-input ${errors.usernameOrEmail ? 'form-input-error' : ''}`}
              placeholder="Enter your username or email"
              {...register('usernameOrEmail', {
                required: 'Username or email is required',
                pattern: {
                  value: /^[^\s@]+@[^\s@]+\.[^\s@]+$|^[a-zA-Z0-9_]+$/,
                  message: 'Please enter a valid email address or username',
                },
              })}
            />
            {errors.usernameOrEmail && (
              <span className="form-error">{errors.usernameOrEmail.message}</span>
            )}
          </div>

          {error && (
            <div className="form-error" style={{ marginBottom: '1rem' }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            className="login-button"
            disabled={isSubmitting || isLoading}
          >
            {isSubmitting || isLoading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}

export default LoginPage

