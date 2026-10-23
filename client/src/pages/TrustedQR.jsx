import React, { useEffect, useState, useCallback } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { ShieldCheck, Plus, Trash2, AlertCircle, X, Globe, Tag, FileText } from 'lucide-react'
import apiClient from '../api/client.js'
import LoadingSpinner from '../components/LoadingSpinner.jsx'
import toast from 'react-hot-toast'

const schema = z.object({
  expectedDestination: z.string().url('Must be a valid URL (https://...)'),
  label: z.string().min(1, 'Label is required').max(80, 'Max 80 characters'),
  description: z.string().max(255, 'Max 255 characters').optional(),
})

function TrustedQRCard({ item, onRevoke, revoking }) {
  const domain = (() => {
    try {
      return new URL(item.expectedDestination).hostname
    } catch {
      return item.expectedDestination
    }
  })()

  return (
    <div className="flex items-start gap-4 p-4 rounded-xl bg-[#0d1426] border border-[#1f2937] hover:border-[#00d4ff]/20 transition-colors">
      <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center flex-shrink-0">
        <ShieldCheck className="w-5 h-5 text-emerald-400" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2">
          <div>
            <p className="text-sm font-semibold text-gray-200">{item.label}</p>
            <p className="text-xs font-mono text-[#00d4ff] mt-0.5">{domain}</p>
          </div>
          <button
            onClick={() => onRevoke(item._id || item.id)}
            disabled={revoking}
            className="flex-shrink-0 p-1.5 rounded-lg text-gray-600 hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50"
            title="Revoke"
          >
            {revoking ? <LoadingSpinner size="sm" /> : <Trash2 className="w-4 h-4" />}
          </button>
        </div>
        {item.description && (
          <p className="text-xs text-gray-500 mt-1.5">{item.description}</p>
        )}
        <p className="text-xs text-gray-700 mt-2 font-mono break-all">{item.expectedDestination}</p>
        <p className="text-xs text-gray-700 mt-1">
          Added{' '}
          {item.createdAt
            ? new Date(item.createdAt).toLocaleDateString('en-US', { dateStyle: 'medium' })
            : '—'}
        </p>
      </div>
    </div>
  )
}

export default function TrustedQR() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [revokingId, setRevokingId] = useState(null)
  const [serverError, setServerError] = useState('')

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm({ resolver: zodResolver(schema) })

  const fetchItems = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await apiClient.get('/api/trusted-qr')
      const data = res.data
      setItems(data?.trustedQRs ?? data?.data ?? [])
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load trusted QR destinations')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchItems()
  }, [fetchItems])

  const onSubmit = async (data) => {
    setServerError('')
    try {
      await apiClient.post('/api/trusted-qr', data)
      toast.success('Trusted destination registered')
      reset()
      setShowForm(false)
      fetchItems()
    } catch (err) {
      setServerError(err?.response?.data?.message || 'Failed to register destination')
    }
  }

  const handleRevoke = async (id) => {
    if (!window.confirm('Revoke this trusted destination?')) return
    setRevokingId(id)
    try {
      await apiClient.delete(`/api/trusted-qr/${id}`)
      toast.success('Destination revoked')
      setItems((prev) => prev.filter((i) => (i._id || i.id) !== id))
    } catch {
      toast.error('Failed to revoke destination')
    } finally {
      setRevokingId(null)
    }
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6 fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
            Trusted QR Destinations
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            Pre-register legitimate QR destinations to reduce false positives
          </p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6] text-[#0a0f1e] font-semibold text-sm transition-colors"
        >
          {showForm ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {showForm ? 'Cancel' : 'Register New'}
        </button>
      </div>

      {/* Register form */}
      {showForm && (
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
          <h2 className="text-sm font-semibold text-gray-300 mb-5">Register Trusted Destination</h2>
          {serverError && (
            <div className="flex items-start gap-2 mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              {serverError}
            </div>
          )}
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">
                <Globe className="w-4 h-4 inline mr-1.5 mb-0.5" />
                Destination URL
              </label>
              <input
                type="url"
                placeholder="https://company.com/landing-page"
                {...register('expectedDestination')}
                className={`w-full px-4 py-3 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${errors.expectedDestination ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              {errors.expectedDestination && (
                <p className="mt-1.5 text-xs text-red-400">{errors.expectedDestination.message}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">
                <Tag className="w-4 h-4 inline mr-1.5 mb-0.5" />
                Label
              </label>
              <input
                type="text"
                placeholder="Company landing page"
                {...register('label')}
                className={`w-full px-4 py-3 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${errors.label ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              {errors.label && (
                <p className="mt-1.5 text-xs text-red-400">{errors.label.message}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">
                <FileText className="w-4 h-4 inline mr-1.5 mb-0.5" />
                Description{' '}
                <span className="text-gray-600 font-normal">(optional)</span>
              </label>
              <textarea
                rows={3}
                placeholder="Brief note about this destination…"
                {...register('description')}
                className={`w-full px-4 py-3 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm resize-none
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${errors.description ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              {errors.description && (
                <p className="mt-1.5 text-xs text-red-400">{errors.description.message}</p>
              )}
            </div>

            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={() => { setShowForm(false); reset(); setServerError('') }}
                className="flex-1 py-3 rounded-xl border border-[#1f2937] text-gray-400 hover:text-white hover:border-gray-600 text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl
                           bg-[#00d4ff] hover:bg-[#00bde6] text-[#0a0f1e] font-semibold text-sm
                           transition-colors disabled:opacity-60"
              >
                {isSubmitting && <LoadingSpinner size="sm" className="border-t-[#0a0f1e]" />}
                Register Destination
              </button>
            </div>
          </form>
        </div>
      )}

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-24">
          <LoadingSpinner size="xl" />
        </div>
      ) : error ? (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-3">
          <AlertCircle className="w-10 h-10 text-red-400" />
          <p className="text-gray-400 text-sm">{error}</p>
          <button onClick={fetchItems} className="text-[#00d4ff] hover:underline text-sm">
            Try again
          </button>
        </div>
      ) : items.length === 0 && !showForm ? (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-3 bg-[#111827] border border-[#1f2937] rounded-2xl">
          <ShieldCheck className="w-12 h-12 text-gray-700" />
          <p className="text-gray-500 text-sm">No trusted destinations yet</p>
          <p className="text-gray-700 text-xs max-w-xs">
            Register known legitimate QR destinations to help the scanner avoid flagging them as threats
          </p>
          <button
            onClick={() => setShowForm(true)}
            className="mt-2 text-[#00d4ff] hover:underline text-sm"
          >
            Register your first destination
          </button>
        </div>
      ) : (
        items.length > 0 && (
          <div className="space-y-3">
            {items.map((item) => (
              <TrustedQRCard
                key={item._id || item.id}
                item={item}
                onRevoke={handleRevoke}
                revoking={revokingId === (item._id || item.id)}
              />
            ))}
          </div>
        )
      )}
    </div>
  )
}
