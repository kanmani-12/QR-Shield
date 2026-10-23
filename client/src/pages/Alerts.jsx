import React, { useEffect, useState, useCallback } from 'react'
import {
  Bell,
  CheckCheck,
  Check,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  AlertTriangle,
  Info,
} from 'lucide-react'
import apiClient from '../api/client.js'
import LoadingSpinner from '../components/LoadingSpinner.jsx'
import toast from 'react-hot-toast'

const SEVERITY_CONFIG = {
  critical: { icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', label: 'Critical' },
  high: { icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', label: 'High' },
  medium: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', label: 'Medium' },
  low: { icon: Info, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', label: 'Low' },
  info: { icon: Info, color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20', label: 'Info' },
}

function AlertItem({ alert, onMarkRead }) {
  const severity = alert.severity?.toLowerCase() || 'info'
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info
  const Icon = cfg.icon

  return (
    <div
      className={`flex items-start gap-4 p-4 rounded-xl border transition-all
        ${alert.isRead ? 'bg-[#0d1426]/50 border-[#1f2937]/50 opacity-70' : `${cfg.bg} ${cfg.border}`}`}
    >
      <div className={`w-9 h-9 rounded-xl ${cfg.bg} ${cfg.color} flex items-center justify-center flex-shrink-0`}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2">
          <div>
            <p className={`text-sm font-semibold ${alert.isRead ? 'text-gray-500' : 'text-gray-200'}`}>
              {alert.title || alert.type || 'Alert'}
            </p>
            {alert.message && (
              <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{alert.message}</p>
            )}
            {alert.url && (
              <p className="text-xs font-mono text-gray-600 mt-1 truncate">{alert.url}</p>
            )}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`text-xs px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border} capitalize`}>
              {cfg.label}
            </span>
            {!alert.isRead && (
              <button
                onClick={() => onMarkRead(alert._id || alert.id)}
                className="p-1.5 rounded-lg text-gray-600 hover:text-emerald-400 hover:bg-emerald-500/10 transition-colors"
                title="Mark as read"
              >
                <Check className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
        <p className="text-xs text-gray-700 mt-2">
          {alert.createdAt
            ? new Date(alert.createdAt).toLocaleString('en-US', {
                dateStyle: 'medium',
                timeStyle: 'short',
              })
            : '—'}
        </p>
      </div>
    </div>
  )
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [unreadCount, setUnreadCount] = useState(0)
  const [markingAll, setMarkingAll] = useState(false)
  const LIMIT = 15

  const fetchAlerts = useCallback(async (p = 1) => {
    setLoading(true)
    setError('')
    try {
      const res = await apiClient.get('/api/alerts', { params: { page: p, limit: LIMIT } })
      const data = res.data
      const list = data?.alerts ?? data?.data ?? []
      const pagination = data?.pagination ?? {}
      setAlerts(list)
      setTotalPages(pagination.pages ?? 1)
      setUnreadCount(list.filter((a) => !a.isRead).length)
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load alerts')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAlerts(page)
  }, [page, fetchAlerts])

  const handleMarkRead = async (id) => {
    try {
      await apiClient.patch(`/api/alerts/${id}/read`)
      setAlerts((prev) =>
        prev.map((a) => (a._id === id || a.id === id ? { ...a, isRead: true } : a)),
      )
      setUnreadCount((c) => Math.max(0, c - 1))
    } catch {
      toast.error('Failed to mark alert as read')
    }
  }

  const handleMarkAllRead = async () => {
    setMarkingAll(true)
    try {
      await apiClient.post('/api/alerts/mark-all-read')
      setAlerts((prev) => prev.map((a) => ({ ...a, isRead: true })))
      setUnreadCount(0)
      toast.success('All alerts marked as read')
    } catch {
      toast.error('Failed to mark all as read')
    } finally {
      setMarkingAll(false)
    }
  }

  return (
    <div className="space-y-6 fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bell className="w-6 h-6 text-[#00d4ff]" />
            Alerts
            {unreadCount > 0 && (
              <span className="ml-2 px-2 py-0.5 rounded-full bg-red-500 text-white text-xs font-bold">
                {unreadCount}
              </span>
            )}
          </h1>
          <p className="text-gray-500 text-sm mt-1">Security alerts and threat notifications</p>
        </div>
        {unreadCount > 0 && (
          <button
            onClick={handleMarkAllRead}
            disabled={markingAll}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-[#1f2937] text-gray-400 hover:text-white hover:border-gray-600 text-sm font-medium transition-colors disabled:opacity-60"
          >
            {markingAll ? <LoadingSpinner size="sm" /> : <CheckCheck className="w-4 h-4" />}
            Mark all read
          </button>
        )}
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center py-24">
          <LoadingSpinner size="xl" />
        </div>
      ) : error ? (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-3">
          <AlertCircle className="w-10 h-10 text-red-400" />
          <p className="text-gray-400 text-sm">{error}</p>
          <button onClick={() => fetchAlerts(page)} className="text-[#00d4ff] hover:underline text-sm">
            Try again
          </button>
        </div>
      ) : alerts.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-3">
          <Bell className="w-12 h-12 text-gray-700" />
          <p className="text-gray-500 text-sm">No alerts yet</p>
          <p className="text-gray-700 text-xs">Alerts appear here when threats are detected</p>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <AlertItem
              key={alert._id || alert.id}
              alert={alert}
              onMarkRead={handleMarkRead}
            />
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-gray-500">Page {page} of {totalPages}</p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 disabled:opacity-40 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 disabled:opacity-40 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
