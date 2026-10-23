import React, { useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Link2, Upload, AlertCircle, ScanLine, X, ImageIcon } from 'lucide-react'
import apiClient from '../api/client.js'
import LoadingSpinner from '../components/LoadingSpinner.jsx'
import toast from 'react-hot-toast'

function classNames(...classes) {
  return classes.filter(Boolean).join(' ')
}

// ── jsQR decoder ─────────────────────────────────────────────────────────────
async function decodeQRFromFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      const img = new Image()
      img.onload = () => {
        const canvas = document.createElement('canvas')
        canvas.width = img.width
        canvas.height = img.height
        const ctx = canvas.getContext('2d')
        ctx.drawImage(img, 0, 0)
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
        import('jsqr').then(({ default: jsQR }) => {
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'dontInvert',
          })
          if (code) {
            resolve(code.data)
          } else {
            reject(new Error('No QR code found in the image. Please try a clearer photo.'))
          }
        })
      }
      img.onerror = () => reject(new Error('Failed to load image'))
      img.src = e.target.result
    }
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.readAsDataURL(file)
  })
}

// ── URL Tab ──────────────────────────────────────────────────────────────────
function URLTab({ onScan }) {
  const [url, setUrl] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    const trimmed = url.trim()
    if (!trimmed) {
      setError('Please enter a URL to scan')
      return
    }
    if (!/^https?:\/\//i.test(trimmed)) {
      setError('URL must start with http:// or https://')
      return
    }
    setLoading(true)
    try {
      await onScan({ url: trimmed, scanType: 'url_direct', inspectRedirects: true })
    } catch (err) {
      setError(err?.response?.data?.message || err?.message || 'Scan failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">URL to scan</label>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Link2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="url"
              value={url}
              onChange={(e) => { setUrl(e.target.value); setError('') }}
              placeholder="https://example.com/suspicious-link"
              className={classNames(
                'w-full pl-10 pr-4 py-3 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm',
                'transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30',
                error ? 'border-red-500/60' : 'border-[#1f2937]',
              )}
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6]
                       text-[#0a0f1e] font-semibold text-sm transition-colors
                       disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {loading ? <LoadingSpinner size="sm" className="border-t-[#0a0f1e]" /> : <ScanLine className="w-4 h-4" />}
            {loading ? 'Scanning…' : 'Scan'}
          </button>
        </div>
        {error && (
          <div className="mt-2 flex items-center gap-1.5 text-red-400 text-xs">
            <AlertCircle className="w-3.5 h-3.5" />
            {error}
          </div>
        )}
      </div>

      <p className="text-xs text-gray-600">
        We analyze redirects, SSL, phishing signals, and check against VirusTotal & Google Safe Browsing.
      </p>
    </form>
  )
}

// ── QR Upload Tab ─────────────────────────────────────────────────────────────
function QRTab({ onScan }) {
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState(null)
  const [decodedUrl, setDecodedUrl] = useState('')
  const [decodeError, setDecodeError] = useState('')
  const [decoding, setDecoding] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scanError, setScanError] = useState('')
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef()

  const handleFile = useCallback(async (f) => {
    if (!f || !f.type.startsWith('image/')) {
      setDecodeError('Please upload a valid image file (PNG, JPG, etc.)')
      return
    }
    setFile(f)
    setDecodeError('')
    setDecodedUrl('')
    setScanError('')

    const objectUrl = URL.createObjectURL(f)
    setPreview(objectUrl)

    setDecoding(true)
    try {
      const url = await decodeQRFromFile(f)
      setDecodedUrl(url)
    } catch (err) {
      setDecodeError(err.message)
    } finally {
      setDecoding(false)
    }
  }, [])

  const handleDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const dropped = e.dataTransfer.files[0]
    if (dropped) handleFile(dropped)
  }

  const handleScan = async () => {
    setScanError('')
    setScanning(true)
    try {
      await onScan({ url: decodedUrl, scanType: 'qr_upload', inspectRedirects: true })
    } catch (err) {
      setScanError(err?.response?.data?.message || err?.message || 'Scan failed. Please try again.')
    } finally {
      setScanning(false)
    }
  }

  const reset = () => {
    setFile(null)
    setPreview(null)
    setDecodedUrl('')
    setDecodeError('')
    setScanError('')
  }

  return (
    <div className="space-y-4">
      {/* Drop zone */}
      {!file ? (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
          className={classNames(
            'border-2 border-dashed rounded-2xl p-12 flex flex-col items-center justify-center cursor-pointer transition-all',
            dragging
              ? 'border-[#00d4ff] bg-[#00d4ff]/5'
              : 'border-[#1f2937] hover:border-[#00d4ff]/50 hover:bg-white/2',
          )}
        >
          <ImageIcon className="w-12 h-12 text-gray-600 mb-3" />
          <p className="text-sm font-medium text-gray-400">Drop a QR code image here</p>
          <p className="text-xs text-gray-600 mt-1">or click to browse files</p>
          <p className="text-xs text-gray-700 mt-3">PNG, JPG, WEBP supported</p>
          <input
            ref={inputRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={(e) => handleFile(e.target.files[0])}
          />
        </div>
      ) : (
        <div className="space-y-4">
          {/* Preview */}
          <div className="flex items-start gap-4 p-4 rounded-xl bg-[#0d1426] border border-[#1f2937]">
            <img
              src={preview}
              alt="QR code preview"
              className="w-24 h-24 object-contain rounded-lg border border-[#1f2937]"
            />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-300 truncate">{file.name}</p>
              <p className="text-xs text-gray-600 mt-0.5">{(file.size / 1024).toFixed(1)} KB</p>

              {decoding && (
                <div className="flex items-center gap-2 mt-3 text-xs text-[#00d4ff]">
                  <LoadingSpinner size="sm" />
                  Decoding QR code…
                </div>
              )}

              {decodedUrl && !decoding && (
                <div className="mt-3">
                  <p className="text-xs text-gray-500 mb-1">Decoded URL:</p>
                  <p className="text-xs font-mono text-emerald-400 break-all">{decodedUrl}</p>
                </div>
              )}

              {decodeError && (
                <div className="mt-3 flex items-center gap-1.5 text-red-400 text-xs">
                  <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                  {decodeError}
                </div>
              )}
            </div>
            <button onClick={reset} className="text-gray-600 hover:text-gray-300 transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {scanError && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {scanError}
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={reset}
              className="flex-1 py-3 rounded-xl border border-[#1f2937] text-gray-400 hover:text-white hover:border-gray-600 text-sm font-medium transition-colors"
            >
              Upload different image
            </button>
            <button
              onClick={handleScan}
              disabled={!decodedUrl || scanning}
              className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl
                         bg-[#00d4ff] hover:bg-[#00bde6] text-[#0a0f1e] font-semibold text-sm
                         transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {scanning ? <LoadingSpinner size="sm" className="border-t-[#0a0f1e]" /> : <ScanLine className="w-4 h-4" />}
              {scanning ? 'Scanning…' : 'Scan QR URL'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Scanner page ─────────────────────────────────────────────────────────
export default function Scanner() {
  const [tab, setTab] = useState('url')
  const navigate = useNavigate()

  const handleScan = async (payload) => {
    const res = await apiClient.post('/api/scans', payload)
    const scanId = res.data?.scanId || res.data?.data?.scanId || res.data?._id || res.data?.data?._id
    if (scanId) {
      toast.success('Scan complete!')
      navigate(`/scans/${scanId}`)
    } else {
      throw new Error('No scan ID returned from server')
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6 fade-in-up">
      <div>
        <h1 className="text-2xl font-bold text-white">Threat Scanner</h1>
        <p className="text-gray-500 text-sm mt-1">Analyze URLs and QR codes for security threats</p>
      </div>

      {/* Card */}
      <div className="bg-[#111827] border border-[#1f2937] rounded-2xl overflow-hidden">
        {/* Tabs */}
        <div className="flex border-b border-[#1f2937]">
          {[
            { id: 'url', icon: Link2, label: 'Scan URL' },
            { id: 'qr', icon: Upload, label: 'Upload QR Code' },
          ].map(({ id, icon: Icon, label }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={classNames(
                'flex items-center gap-2 px-6 py-4 text-sm font-medium border-b-2 transition-colors',
                tab === id
                  ? 'border-[#00d4ff] text-[#00d4ff] bg-[#00d4ff]/5'
                  : 'border-transparent text-gray-500 hover:text-gray-300',
              )}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="p-6">
          {tab === 'url' ? <URLTab onScan={handleScan} /> : <QRTab onScan={handleScan} />}
        </div>
      </div>

      {/* Info card */}
      <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-5">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">What we check</h3>
        <div className="grid grid-cols-2 gap-2 text-xs text-gray-500">
          {[
            '🔍 URL structure & hostname',
            '🛡️ VirusTotal scan',
            '🔒 SSL certificate validation',
            '🌐 Google Safe Browsing',
            '↩️ Redirect chain inspection',
            '🤖 AI threat explanation',
          ].map((item) => (
            <div key={item} className="flex items-center gap-1.5">
              <span>{item}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
