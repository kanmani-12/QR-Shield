import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  History,
  ChevronLeft,
  ChevronRight,
  Trash2,
  ExternalLink,
  AlertCircle,
  Search,
} from 'lucide-react'
import apiClient from '../api/client.js'
import RiskBadge from '../components/RiskBadge.jsx'
import LoadingSpinner from '../components/LoadingSpinner.jsx'
import toast from 'react-hot-toast'

const SCAN_TYPE_LABELS = {
  url_direct: 'URL',
  qr_upload: 'QR Upload',
  api: 'API',
}

export default function ScanHistory() {
  const navigate = useNavigate()
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)
  const [deletingId, setDeletingId] = useState(null)
  const [search, setSearch] = useState('')
  const LIMIT = 10

  const fetchScans = useCallback(async (p = 1) => {
    setLoading(true)
    setError('')
    try {
      const res = await apiClient.get('/api/scans', { params: { page: p, limit: LIMIT } })
      const data = res.data
      const list = data?.scans ?? data?.data ?? []
      const pagination = data?.pagination ?? {}
      setScans(list)
      setTotal(pagination.total ?? list.length)
      setTotalPages(pagination.pages ?? Math.ceil((pagination.total ?? list.length) / LIMIT))
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load scan history')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchScans(page)
  }, [page, fetchScans])

  const handleDelete = async (e, id) => {
    e.stopPropagation()
    if (!window.confirm('Delete this scan?')) return
    setDeletingId(id)
    try {
      await apiClient.delete(`/api/scans/${id}`)
      toast.success('Scan deleted')
      fetchScans(page)
    } catch {
      toast.error('Failed to delete scan')
    } finally {
      setDeletingId(null)
    }
  }

  const filteredScans = scans.filter((s) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      (s.destinationHostname || '').toLowerCase().includes(q) ||
      (s.url || '').toLowerCase().includes(q) ||
      (s.riskLevel || '').toLowerCase().includes(q)
    )
  })

  return (
    <div className="space-y-6 fade-in-up">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <History className="w-6 h-6 text-[#00d4ff]" />
            Scan History
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            {total} total scan{total !== 1 ? 's' : ''}
          </p>
        </div>
        <button
          onClick={() => navigate('/scanner')}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6] text-[#0a0f1e] font-semibold text-sm transition-colors"
        >
          New Scan
        </button>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          type="text"
          placeholder="Search by hostname, URL, or risk level…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-10 pr-4 py-3 rounded-xl bg-[#111827] border border-[#1f2937] text-white placeholder-gray-600 text-sm
                     focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30 transition-colors"
        />
      </div>

      {/* Content */}
      <div className="bg-[#111827] border border-[#1f2937] rounded-2xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-24">
            <LoadingSpinner size="xl" />
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-24 text-center space-y-3">
            <AlertCircle className="w-10 h-10 text-red-400" />
            <p className="text-gray-400 text-sm">{error}</p>
            <button
              onClick={() => fetchScans(page)}
              className="text-[#00d4ff] hover:underline text-sm"
            >
              Try again
            </button>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-center space-y-3">
            <History className="w-12 h-12 text-gray-700" />
            <p className="text-gray-500 text-sm">
              {search ? 'No scans match your search' : 'No scans yet'}
            </p>
            {!search && (
              <button
                onClick={() => navigate('/scanner')}
                className="text-[#00d4ff] hover:underline text-sm"
              >
                Run your first scan
              </button>
            )}
          </div>
        ) : (
          <>
            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1f2937]">
                    {['Date', 'Hostname / URL', 'Type', 'Risk Level', 'Score', 'Actions'].map((h) => (
                      <th
                        key={h}
                        className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1f2937]">
                  {filteredScans.map((scan) => {
                    const sid = scan._id || scan.id
                    return (
                      <tr
                        key={sid}
                        onClick={() => navigate(`/scans/${sid}`)}
                        className="table-row-hover transition-colors group"
                      >
                        <td className="px-4 py-4 text-xs text-gray-500 whitespace-nowrap">
                          {scan.createdAt
                            ? new Date(scan.createdAt).toLocaleDateString('en-US', {
                                month: 'short',
                                day: 'numeric',
                                year: '2-digit',
                              })
                            : '—'}
                        </td>
                        <td className="px-4 py-4 max-w-xs">
                          <p className="text-sm text-gray-300 font-mono truncate group-hover:text-white transition-colors">
                            {scan.destinationHostname || 'Unknown'}
                          </p>
                          <p className="text-xs text-gray-600 truncate">
                            {scan.url || scan.originalUrl || ''}
                          </p>
                        </td>
                        <td className="px-4 py-4 text-xs text-gray-500 whitespace-nowrap">
                          {SCAN_TYPE_LABELS[scan.scanType] || scan.scanType || '—'}
                        </td>
                        <td className="px-4 py-4">
                          <RiskBadge level={scan.riskLevel} size="sm" />
                        </td>
                        <td className="px-4 py-4 text-sm font-mono text-gray-400">
                          {scan.riskScore ?? '—'}
                        </td>
                        <td className="px-4 py-4">
                          <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                            <button
                              onClick={() => navigate(`/scans/${sid}`)}
                              className="p-1.5 text-gray-500 hover:text-[#00d4ff] rounded transition-colors"
                              title="View"
                            >
                              <ExternalLink className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => handleDelete(e, sid)}
                              disabled={deletingId === sid}
                              className="p-1.5 text-gray-500 hover:text-red-400 rounded transition-colors disabled:opacity-50"
                              title="Delete"
                            >
                              {deletingId === sid ? (
                                <LoadingSpinner size="sm" />
                              ) : (
                                <Trash2 className="w-4 h-4" />
                              )}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-4 border-t border-[#1f2937]">
                <p className="text-xs text-gray-500">
                  Page {page} of {totalPages}
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    const p = Math.max(1, Math.min(totalPages - 4, page - 2)) + i
                    return (
                      <button
                        key={p}
                        onClick={() => setPage(p)}
                        className={`w-8 h-8 rounded-lg text-sm transition-colors ${
                          p === page
                            ? 'bg-[#00d4ff] text-[#0a0f1e] font-bold'
                            : 'text-gray-400 hover:text-white hover:bg-white/5'
                        }`}
                      >
                        {p}
                      </button>
                    )
                  })}
                  <button
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
