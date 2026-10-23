import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ScanLine,
  Bell,
  Shield,
  AlertTriangle,
  TrendingUp,
  ExternalLink,
  Clock,
} from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import { useAuth } from '../hooks/useAuth.js'
import apiClient from '../api/client.js'
import RiskBadge from '../components/RiskBadge.jsx'
import LoadingSpinner from '../components/LoadingSpinner.jsx'

const RISK_COLORS = {
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
  UNKNOWN: '#6b7280',
}

function StatCard({ icon: Icon, label, value, color = 'cyan', loading }) {
  const colorMap = {
    cyan: 'text-[#00d4ff] bg-[#00d4ff]/10 border-[#00d4ff]/20',
    red: 'text-red-400 bg-red-500/10 border-red-500/20',
    green: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    yellow: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  }

  return (
    <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-5 flex items-center gap-4">
      <div className={`w-12 h-12 rounded-xl border flex items-center justify-center flex-shrink-0 ${colorMap[color]}`}>
        <Icon className="w-6 h-6" />
      </div>
      <div>
        <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
        {loading ? (
          <LoadingSpinner size="sm" className="mt-1" />
        ) : (
          <p className="text-2xl font-bold text-white font-mono mt-0.5">{value}</p>
        )}
      </div>
    </div>
  )
}

function DemoWarning() {
  return (
    <div className="flex items-start gap-3 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-sm mb-6">
      <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
      <div>
        <p className="font-semibold">Demo Mode Active</p>
        <p className="text-yellow-400/80 text-xs mt-0.5">
          Some results are simulated because external threat intelligence APIs are unavailable. Results may not reflect real-world threats.
        </p>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { user } = useAuth()
  const navigate = useNavigate()

  const [stats, setStats] = useState({ total: 0, unread: 0, high: 0 })
  const [riskDist, setRiskDist] = useState([])
  const [recentScans, setRecentScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [hasDemo, setHasDemo] = useState(false)

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [scansRes, notifRes, distRes, recentRes] = await Promise.allSettled([
          apiClient.get('/api/scans', { params: { limit: 1, page: 1 } }),
          apiClient.get('/api/notifications'),
          apiClient.get('/api/analytics/risk-distribution'),
          apiClient.get('/api/scans', { params: { limit: 5, page: 1 } }),
        ])

        const total =
          scansRes.status === 'fulfilled'
            ? scansRes.value.data?.pagination?.total ?? scansRes.value.data?.total ?? 0
            : 0

        const unread =
          notifRes.status === 'fulfilled'
            ? notifRes.value.data?.unreadCount ?? notifRes.value.data?.data?.unreadCount ?? 0
            : 0

        let distData = []
        if (distRes.status === 'fulfilled') {
          const raw = distRes.value.data?.data ?? distRes.value.data ?? {}
          distData = Object.entries(raw)
            .filter(([key]) => ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(key))
            .map(([key, val]) => ({ name: key, value: typeof val === 'number' ? val : 0 }))
            .filter((d) => d.value > 0)
        }

        let recent = []
        let highCount = 0
        let demoFound = false
        if (recentRes.status === 'fulfilled') {
          recent = recentRes.value.data?.scans ?? recentRes.value.data?.data ?? []
          highCount = recent.filter((s) => s.riskLevel === 'HIGH').length
          demoFound = recent.some((s) => s.isDemo)
        }

        setStats({ total, unread, high: highCount })
        setRiskDist(distData)
        setRecentScans(recent)
        setHasDemo(demoFound)
      } catch {
        // silently fail
      } finally {
        setLoading(false)
      }
    }
    fetchAll()
  }, [])

  const firstName = user?.name?.split(' ')[0] || 'there'

  return (
    <div className="space-y-6 fade-in-up">
      {/* Welcome banner */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Welcome back, <span className="text-[#00d4ff]">{firstName}</span> 👋
          </h1>
          <p className="text-gray-500 text-sm mt-1">Here's your threat intelligence overview</p>
        </div>
        <button
          onClick={() => navigate('/scanner')}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6] text-[#0a0f1e] font-semibold text-sm transition-colors"
        >
          <ScanLine className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* Demo warning */}
      {hasDemo && <DemoWarning />}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard icon={ScanLine} label="Total Scans" value={stats.total} color="cyan" loading={loading} />
        <StatCard icon={Bell} label="Unread Alerts" value={stats.unread} color="yellow" loading={loading} />
        <StatCard icon={Shield} label="High Risk (Recent)" value={stats.high} color="red" loading={loading} />
      </div>

      {/* Charts + Recent scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk distribution chart */}
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-5 h-5 text-[#00d4ff]" />
            <h2 className="text-base font-semibold text-white">Risk Distribution</h2>
          </div>
          {loading ? (
            <div className="flex items-center justify-center h-48">
              <LoadingSpinner size="lg" />
            </div>
          ) : riskDist.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-gray-600">
              <ScanLine className="w-10 h-10 mb-2 opacity-40" />
              <p className="text-sm">No scan data yet</p>
              <p className="text-xs mt-1">Run your first scan to see analytics</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={riskDist}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {riskDist.map((entry) => (
                    <Cell key={entry.name} fill={RISK_COLORS[entry.name] || '#6b7280'} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#0d1426',
                    border: '1px solid #1f2937',
                    borderRadius: '8px',
                    color: '#f9fafb',
                    fontSize: '12px',
                  }}
                />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => (
                    <span style={{ color: '#9ca3af', fontSize: '12px' }}>{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Recent scans */}
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-[#00d4ff]" />
              <h2 className="text-base font-semibold text-white">Recent Scans</h2>
            </div>
            <button
              onClick={() => navigate('/history')}
              className="text-xs text-[#00d4ff] hover:text-[#00bde6] flex items-center gap-1"
            >
              View all <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center h-48">
              <LoadingSpinner size="lg" />
            </div>
          ) : recentScans.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-gray-600">
              <ScanLine className="w-10 h-10 mb-2 opacity-40" />
              <p className="text-sm">No scans yet</p>
              <button
                onClick={() => navigate('/scanner')}
                className="mt-3 text-xs text-[#00d4ff] hover:underline"
              >
                Scan your first URL
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {recentScans.slice(0, 5).map((scan) => (
                <button
                  key={scan._id || scan.id}
                  onClick={() => navigate(`/scans/${scan._id || scan.id}`)}
                  className="w-full flex items-center gap-3 p-3 rounded-xl bg-[#0d1426] hover:bg-[#0d1426]/80 border border-[#1f2937] hover:border-[#00d4ff]/30 transition-all text-left group"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-300 truncate font-mono group-hover:text-white transition-colors">
                      {scan.destinationHostname || scan.url || 'Unknown URL'}
                    </p>
                    <p className="text-xs text-gray-600 mt-0.5">
                      {scan.createdAt
                        ? new Date(scan.createdAt).toLocaleDateString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : '—'}
                    </p>
                  </div>
                  <RiskBadge level={scan.riskLevel} size="sm" />
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
