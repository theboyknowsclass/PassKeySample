import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import { isPasskeyRegistrationEnabled } from './config/appConfig'
import './App.css'

function App() {
  const registrationEnabled = isPasskeyRegistrationEnabled()

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        {registrationEnabled && (
          <Route path="/register" element={<RegisterPage />} />
        )}
        <Route path="/" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App

