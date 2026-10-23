import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, User, ChevronDown } from 'lucide-react'
import { useAuth } from '../hooks/useAuth.js'
import apiClient from '../api/client.js'
import toast from 'react-hot-toast'

export default function Topbar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [unread, setUnread] = useState(0)
  const [dropdownOpen, setDropdownOpen] = useState(false)

  useEffect(() => {
    let cancelled = false
    const fetch = async () => {
      try {
        const res = await apiClient.get('/api/notifications')
        if (!cancelled) {
          const data = res.data
          setUnread(data?.unreadCount ?? data?.data?.unreadCount ?? 0)
        }
      } catch {
        // silently fail
      }
    }
    fetch()
    const interval = setInterval(fetch, 30000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  const handleLogout = async () => {
    try {
      await logout()
      toast.success('Logged out')
      navigate('/login')
    } catch {
      navigate('/login')
    }
  }

  const initials = user?.name
    ? user.name
        .split(' ')
        .map((w) => w[0])
        .join('')
        .slice(0, 2)
        .toUpperCase()
    : 'U'

  return (
    <header className="h-14 flex items-center justify-between px-6 bg-[#0d1426] border-b border-[#1f2937] flex-shrink-0">
      {/* App title */}
      <div className="flex items-center gap-2">
        <span className="text-sm font-semibold text-gray-300 hidden sm:block">
          QRShield <span className="text-[#00d4ff]">Sentinel</span>
        </span>
        <span className="hidden sm:block text-gray-600">|</span>
        <span className="text-xs text-gray-500 hidden sm:block">Threat Intelligence Dashboard</span>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3">
        {/* Notification bell */}
        <button
          onClick={() => navigate('/alerts')}
          className="relative p-2 rounded-lg text-gray-400 hover:text-[#00d4ff] hover:bg-[#00d4ff]/10 transition-colors"
          aria-label="Alerts"
        >
          <Bell className="w-5 h-5" />
          {unread > 0 && (
            <span className="absolute top-1 right-1 min-w-[16px] h-4 px-1 rounded-full bg-red-500 text-white text-[9px] font-bold flex items-center justify-center">
              {unread > 99 ? '99+' : unread}
            </span>
          )}
        </button>

        {/* User dropdown */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen((o) => !o)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-white/5 transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-[#00d4ff]/20 border border-[#00d4ff]/30 flex items-center justify-center">
              <span className="text-xs font-bold text-[#00d4ff]">{initials}</span>
            </div>
            <span className="text-sm text-gray-300 hidden sm:block max-w-[120px] truncate">
              {user?.name || user?.email || 'User'}
            </span>
            <ChevronDown className="w-3 h-3 text-gray-500" />
          </button>

          {dropdownOpen && (
            <>
              <div
                className="fixed inset-0 z-10"
                onClick={() => setDropdownOpen(false)}
              />
              <div className="absolute right-0 top-full mt-2 w-48 bg-[#111827] border border-[#1f2937] rounded-xl shadow-xl z-20 overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1f2937]">
                  <p className="text-xs font-medium text-gray-300 truncate">{user?.name}</p>
                  <p className="text-xs text-gray-500 truncate">{user?.email}</p>
                </div>
                <button
                  onClick={() => { setDropdownOpen(false); navigate('/profile') }}
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
                >
                  <User className="w-4 h-4" />
                  Profile
                </button>
                <button
                  onClick={() => { setDropdownOpen(false); handleLogout() }}
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
                >
                  Logout
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
