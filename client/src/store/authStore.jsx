import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import apiClient from '../api/client.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [accessToken, setAccessToken] = useState(() => localStorage.getItem('accessToken') || null)
  const [isLoading, setIsLoading] = useState(true)

  // ── Persist token changes ────────────────────────────────────────────────
  const storeToken = useCallback((token) => {
    if (token) {
      localStorage.setItem('accessToken', token)
    } else {
      localStorage.removeItem('accessToken')
    }
    setAccessToken(token)
  }, [])

  // ── Fetch current user ───────────────────────────────────────────────────
  const fetchMe = useCallback(async () => {
    try {
      const res = await apiClient.get('/api/auth/me')
      setUser(res.data?.user || res.data || null)
    } catch {
      setUser(null)
      storeToken(null)
    }
  }, [storeToken])

  // ── On mount: if we have a token, verify it ──────────────────────────────
  useEffect(() => {
    if (accessToken) {
      fetchMe().finally(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Login ────────────────────────────────────────────────────────────────
  const login = useCallback(async (email, password) => {
    const res = await apiClient.post('/api/auth/login', { email, password })
    const data = res.data
    const token = data?.accessToken || data?.token
    storeToken(token)
    const userData = data?.user || null
    setUser(userData)
    return data
  }, [storeToken])

  // ── Register ─────────────────────────────────────────────────────────────
  const register = useCallback(async (name, email, password) => {
    const res = await apiClient.post('/api/auth/register', { name, email, password })
    const data = res.data
    const token = data?.accessToken || data?.token
    storeToken(token)
    const userData = data?.user || null
    setUser(userData)
    return data
  }, [storeToken])

  // ── Logout ───────────────────────────────────────────────────────────────
  const logout = useCallback(async () => {
    try {
      await apiClient.post('/api/auth/logout')
    } catch {
      // swallow
    } finally {
      storeToken(null)
      setUser(null)
    }
  }, [storeToken])

  // ── Refresh ───────────────────────────────────────────────────────────────
  const refreshAuth = useCallback(async () => {
    try {
      const res = await apiClient.post('/api/auth/refresh')
      const token = res.data?.accessToken
      storeToken(token)
      await fetchMe()
      return token
    } catch {
      storeToken(null)
      setUser(null)
      return null
    }
  }, [storeToken, fetchMe])

  const value = {
    user,
    accessToken,
    isLoading,
    isAuthenticated: !!accessToken && !!user,
    login,
    register,
    logout,
    refreshAuth,
    setUser,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuthContext() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuthContext must be used within AuthProvider')
  return ctx
}

export default AuthContext
