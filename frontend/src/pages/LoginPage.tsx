import { useForm } from 'react-hook-form'
import './LoginPage.css'

interface LoginFormData {
  usernameOrEmail: string
}

function LoginPage() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormData>({
    mode: 'onBlur',
  })

  const onSubmit = async (data: LoginFormData) => {
    // TODO: Implement API call
    console.log('Login attempt:', data)
    
    // Dummy section for now
    await new Promise((resolve) => setTimeout(resolve, 1000))
    alert(`Dummy login: ${data.usernameOrEmail}`)
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

          <button
            type="submit"
            className="login-button"
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}

export default LoginPage

