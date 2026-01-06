import { useForm } from 'react-hook-form'
import { Link } from 'react-router-dom'
import { usePasskeyRegistration } from '../hooks/usePasskeyRegistration'
import './RegisterPage.css'

interface RegisterFormData {
  usernameOrEmail: string
}

function RegisterPage() {
  const { register: registerPasskey, isLoading, error, isSuccess, reset } = usePasskeyRegistration()
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<RegisterFormData>({
    mode: 'onBlur',
  })

  const onSubmit = async (data: RegisterFormData) => {
    try {
      reset()
      await registerPasskey(data.usernameOrEmail)
    } catch (err) {
      // Error is handled by usePasskeyRegistration hook, but we can also set form error
      const errorMessage =
        err instanceof Error ? err.message : 'Registration failed'
      setError('usernameOrEmail', {
        type: 'manual',
        message: errorMessage,
      })
    }
  }

  return (
    <div className="register-container">
      <div className="register-card">
        <h1 className="register-title">Register Passkey</h1>
        <p className="register-subtitle">
          Register a passkey for your account
        </p>

        {isSuccess ? (
          <div className="register-success">
            <div className="success-message">
              <svg
                className="success-icon"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
              <p>Passkey registered successfully!</p>
            </div>
            <Link to="/login" className="login-link">
              Go to Login
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit(onSubmit)} className="register-form">
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
              className="register-button"
              disabled={isSubmitting || isLoading}
            >
              {isSubmitting || isLoading ? 'Registering...' : 'Register Passkey'}
            </button>

            <div className="register-footer">
              <Link to="/login" className="login-link">
                Back to Login
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

export default RegisterPage

