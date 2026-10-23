import React, { useState, useEffect } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  ScanLine,
  History,
  Bell,
  ShieldCheck,
  User,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Shield,
} from 'lucide-react'
import { useAuth } from '../hooks/useAuth.js'
import apiClient from '../api/client.js'
import toast from 'react-hot-toast'

export default function Sidebar({ collapsed, onToggle }) {
  const { logout, user } = useAuth()
  const navigate = useNavigate()
  const [unreadAlerts, setUnreadAlerts] = useState(0)

  useEffect(() => {
    let cancelled = false
    const fetchNotifications = async () => {
      try {
        const res = await apiClient.get('/api/notifications')
        if (!cancelled) {
          const data = res.data
          setUnreadAlerts(data?.unreadCount ?? data?.data?.unreadCount ?? 0)
        }
      } catch {
        // silently fail
      }
    }
    fetchNotifications()
    const interval = setInterval(fetchNotifications, 30000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  const handleLogout = async () => {
    try {
      await logout()
      toast.success('Logged out successfully')
      navigate('/login')
    } catch {
      navigate('/login')
    }
  }

  const navLinks = [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/scanner', icon: ScanLine, label: 'Scanner' },
    { to: '/history', icon: History, label: 'Scan History' },
    { to: '/alerts', icon: Bell, label: 'Alerts', badge: unreadAlerts },
    { to: '/trusted-qr', icon: ShieldCheck, label: 'Trusted QR' },
    { to: '/profile', icon: User, label: 'Profile' },
  ]

  return (
    <aside
      className={`
        flex flex-col h-full bg-[#0d1426] border-r border-[#1f2937]
        transition-all duration-300 ease-in-out
        ${collapsed ? 'w-16' : 'w-64'}
      `}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-[#1f2937]">
        <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-[#00d4ff]/10 border border-[#00d4ff]/30 flex items-center justify-center">
          <Shield className="w-5 h-5 text-[#00d4ff]" />
        </div>
        {!collapsed && (
          <span className="text-sm font-bold text-white tracking-wide whitespace-nowrap">
            QRShield <span className="text-[#00d4ff]">Sentinel</span>
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-1">
        {navLinks.map(({ to, icon: Icon, label, badge }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
               transition-all duration-150 group relative
               ${
                 isActive
                   ? 'sidebar-link-active text-[#00d4ff] bg-[#00d4ff]/10'
                   : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
               }`
            }
            title={collapsed ? label : ''}
          >
            <Icon className="w-5 h-5 flex-shrink-0" />
            {!collapsed && <span className="flex-1">{label}</span>}
            {badge > 0 && (
              <span
                className={`
                  flex-shrink-0 min-w-[18px] h-[18px] px-1 rounded-full
                  bg-red-500 text-white text-[10px] font-bold
                  flex items-center justify-center
                  ${collapsed ? 'absolute top-1 right-1' : ''}
                `}
              >
                {badge > 99 ? '99+' : badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User + Logout */}
      <div className="border-t border-[#1f2937] p-3 space-y-2">
        {!collapsed && user && (
          <div className="px-3 py-2">
            <p className="text-xs text-gray-500 truncate">{user.email}</p>
            <p className="text-xs text-gray-400 capitalize">{user.role || 'user'}</p>
          </div>
        )}
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
                     text-gray-400 hover:text-red-400 hover:bg-red-500/10
                     transition-all duration-150"
          title={collapsed ? 'Logout' : ''}
        >
          <LogOut className="w-5 h-5 flex-shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>

      {/* Collapse toggle */}
      <button
        onClick={onToggle}
        className="absolute -right-3 top-20 w-6 h-6 rounded-full
                   bg-[#0d1426] border border-[#1f2937]
                   flex items-center justify-center
                   text-gray-400 hover:text-[#00d4ff]
                   transition-colors z-10"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronLeft className="w-3 h-3" />}
      </button>
    </aside>
  )
}
