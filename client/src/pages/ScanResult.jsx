import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft,
  Globe,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Info,
  ExternalLink,
  Bot,
  Trash2,
  AlertCircle,
} from 'lucide-react'
import apiClient from '../api/client.js'
import RiskBadge from '../components/RiskBadge.jsx'
import LoadingSpinner from '../components/LoadingSpinner.jsx'
import toast from 'react-hot-toast'

// ── Risk score gauge ──────────────────────────────────────────────────────────
function RiskGauge({ score }) {
  const clamped = Math.min(100, Math.max(0, score || 0))
  const color =
    clamped >= 70
      ? '#ef4444'
      : clamped >= 40
      ? '#f59e0b'
      : '#10b981'

  const radius = 54
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (clamped / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" viewBox="0 0 140 140">
        {/* Background ring */}
        <circle cx="70" cy="70" r={radius} fill="none" stroke="#1f2937" strokeWidth="12" />
        {/* Progress ring */}
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 70 70)"
          style={{ transition: 'stroke-dashoffset 0.8s ease', filter: `drop-shadow(0 0 6px ${color}80)` }}
        />
        {/* Score text */}
        <text x="70" y="65" textAnchor="middle" fill="white" fontSize="28" fontFamily="monospace" fontWeight="bold">
          {clamped}
        </text>
        <text x="70" y="83" textAnchor="middle" fill="#6b7280" fontSize="11">
          RISK SCORE
        </text>
      </svg>
    </div>
  )
}

// ── Severity icon ─────────────────────────────────────────────────────────────
function SeverityIcon({ severity }) {
  const map = {
    high: { icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-500/10' },
    medium: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
    low: { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
    info: { icon: Info, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  }
  const cfg = map[severity?.toLowerCase()] || map.info
  const Icon = cfg.icon
  return (
    <span className={`w-7 h-7 rounded-lg ${cfg.bg} ${cfg.color} flex items-center justify-center flex-shrink-0`}>
      <Icon className="w-4 h-4" />
    </span>
  )
}

// ── Provider status pill ───────────────────────────────────────────────────────
function StatusPill({ status }) {
  const map = {
    clean: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    malicious: 'bg-red-500/20 text-red-400 border-red-500/30',
    suspicious: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    error: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  }
  const cls = map[status?.toLowerCase()] || map.unknown
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${cls} capitalize`}>
      {status || 'unknown'}
    </span>
  )
}

export default function ScanResult() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    const fetchScan = async () => {
      try {
        const res = await apiClient.get(`/api/scans/${id}`)
        setScan(res.data?.scan ?? res.data?.data ?? res.data)
      } catch (err) {
        setError(err?.response?.data?.message || 'Failed to load scan result')
      } finally {
        setLoading(false)
      }
    }
    fetchScan()
  }, [id])

  const handleDelete = async () => {
    if (!window.confirm('Delete this scan result?')) return
    setDeleting(true)
    try {
      await apiClient.delete(`/api/scans/${id}`)
      toast.success('Scan deleted')
      navigate('/history')
    } catch {
      toast.error('Failed to delete scan')
    } finally {
      setDeleting(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <LoadingSpinner size="xl" />
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-4">
        <AlertCircle className="w-12 h-12 text-red-400" />
        <p className="text-gray-300">{error || 'Scan not found'}</p>
        <button onClick={() => navigate('/history')} className="text-[#00d4ff] hover:underline text-sm">
          Back to history
        </button>
      </div>
    )
  }

  const recommendation = scan.recommendation || {}
  const actionColorMap = {
    block: 'bg-red-500/20 border-red-500/40 text-red-300',
    warn: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300',
    proceed_with_caution: 'bg-blue-500/20 border-blue-500/40 text-blue-300',
    proceed: 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300',
  }
  const recColor = actionColorMap[recommendation.action] || actionColorMap.warn

  return (
    <div className="max-w-3xl mx-auto space-y-5 fade-in-up">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/history')}
          className="flex items-center gap-2 text-gray-500 hover:text-gray-300 text-sm transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to History
        </button>
      </div>

      {/* Demo warning */}
      {scan.isDemo && (
        <div className="flex items-start gap-3 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold">Demo Result</p>
            <p className="text-yellow-400/80 text-xs mt-0.5">
              {scan.demoWarning || 'This result is simulated. External APIs were unavailable.'}
            </p>
          </div>
        </div>
      )}

      {/* Hero card */}
      <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
          <RiskGauge score={scan.riskScore} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-3">
              <RiskBadge level={scan.riskLevel} size="lg" />
            </div>
            <div className="flex items-center gap-2 mb-1">
              <Globe className="w-4 h-4 text-gray-500" />
              <p className="text-sm font-mono text-gray-300 break-all">
                {scan.destinationHostname || scan.urlAnalysis?.hostname || 'Unknown host'}
              </p>
            </div>
            <p className="text-xs text-gray-600 font-mono break-all">
              {scan.url || scan.originalUrl || ''}
            </p>
            <p className="text-xs text-gray-600 mt-2">
              Scanned{' '}
              {scan.createdAt
                ? new Date(scan.createdAt).toLocaleString('en-US', {
                    dateStyle: 'medium',
                    timeStyle: 'short',
                  })
                : '—'}
            </p>
          </div>
          <button
            onClick={handleDelete}
            disabled={deleting}
            className="flex-shrink-0 flex items-center gap-2 px-3 py-2 rounded-lg text-gray-500 hover:text-red-400 hover:bg-red-500/10 transition-colors text-sm"
          >
            {deleting ? <LoadingSpinner size="sm" /> : <Trash2 className="w-4 h-4" />}
            Delete
          </button>
        </div>
      </div>

      {/* Recommendation */}
      {(recommendation.action || recommendation.messageEn) && (
        <div className={`flex items-start gap-3 p-4 rounded-xl border ${recColor}`}>
          <ShieldAlert className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide">
              {(recommendation.action || '').replace(/_/g, ' ')}
            </p>
            {recommendation.messageEn && (
              <p className="text-xs mt-1 opacity-80">{recommendation.messageEn}</p>
            )}
          </div>
        </div>
      )}

      {/* Evidence list */}
      {scan.evidence && scan.evidence.length > 0 && (
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">
            Evidence ({scan.evidence.length} {scan.evidence.length === 1 ? 'factor' : 'factors'})
          </h2>
          <div className="space-y-3">
            {scan.evidence.map((ev, i) => (
              <div
                key={i}
                className="flex items-start gap-3 p-3 rounded-xl bg-[#0d1426] border border-[#1f2937]"
              >
                <SeverityIcon severity={ev.severity} />
                <div className="min-w-0">
                  <p className="text-sm font-medium text-gray-300">{ev.factor}</p>
                  {ev.description && (
                    <p className="text-xs text-gray-500 mt-0.5">{ev.description}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Provider results */}
      {scan.providerResults && scan.providerResults.length > 0 && (
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Threat Intelligence Providers</h2>
          <div className="space-y-3">
            {scan.providerResults.map((p, i) => (
              <div
                key={i}
                className="flex items-center justify-between p-3 rounded-xl bg-[#0d1426] border border-[#1f2937]"
              >
                <div>
                  <p className="text-sm font-medium text-gray-300">{p.provider}</p>
                  {p.details && <p className="text-xs text-gray-500 mt-0.5">{p.details}</p>}
                </div>
                <StatusPill status={p.status} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* URL Flags */}
      {scan.urlAnalysis?.flags && scan.urlAnalysis.flags.length > 0 && (
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">URL Analysis Flags</h2>
          <div className="flex flex-wrap gap-2">
            {scan.urlAnalysis.flags.map((flag, i) => (
              <span
                key={i}
                className="px-2.5 py-1 rounded-lg bg-[#0d1426] border border-[#1f2937] text-xs text-gray-400 font-mono"
              >
                {flag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* AI Explanation */}
      {scan.aiExplanation && (
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Bot className="w-5 h-5 text-[#00d4ff]" />
            <h2 className="text-sm font-semibold text-gray-300">AI Analysis</h2>
          </div>
          {scan.aiExplanation.en && (
            <div className="mb-3">
              <p className="text-xs text-gray-500 mb-1.5 uppercase tracking-wider">English</p>
              <p className="text-sm text-gray-300 leading-relaxed">{scan.aiExplanation.en}</p>
            </div>
          )}
          {scan.aiExplanation.ta && (
            <div className="mt-4 pt-4 border-t border-[#1f2937]">
              <p className="text-xs text-gray-500 mb-1.5 uppercase tracking-wider">Tamil</p>
              <p className="text-sm text-gray-300 leading-relaxed">{scan.aiExplanation.ta}</p>
            </div>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-3">
        <button
          onClick={() => navigate('/history')}
          className="flex-1 py-3 rounded-xl border border-[#1f2937] text-gray-400 hover:text-white hover:border-gray-600 text-sm font-medium transition-colors"
        >
          Back to History
        </button>
        <button
          onClick={() => navigate('/scanner')}
          className="flex-1 py-3 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6] text-[#0a0f1e] font-semibold text-sm transition-colors"
        >
          New Scan
        </button>
      </div>
    </div>
  )
}
