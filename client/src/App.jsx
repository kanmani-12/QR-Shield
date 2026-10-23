import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { AuthProvider } from './store/authStore.jsx'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Register from './pages/Register.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Scanner from './pages/Scanner.jsx'
import ScanResult from './pages/ScanResult.jsx'
import ScanHistory from './pages/ScanHistory.jsx'
import Alerts from './pages/Alerts.jsx'
import TrustedQR from './pages/TrustedQR.jsx'
import Profile from './pages/Profile.jsx'
import NotFound from './pages/NotFound.jsx'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#111827',
              color: '#f9fafb',
              border: '1px solid #1f2937',
            },
            success: {
              iconTheme: { primary: '#10b981', secondary: '#111827' },
            },
            error: {
              iconTheme: { primary: '#ef4444', secondary: '#111827' },
            },
          }}
        />
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<Layout />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scanner" element={<Scanner />} />
              <Route path="/scans/:id" element={<ScanResult />} />
              <Route path="/history" element={<ScanHistory />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/trusted-qr" element={<TrustedQR />} />
              <Route path="/profile" element={<Profile />} />
            </Route>
          </Route>

          {/* Redirects */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
