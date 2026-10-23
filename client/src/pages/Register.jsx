import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Shield, Eye, EyeOff, AlertCircle, Check, X } from 'lucide-react'
import { useAuth } from '../hooks/useAuth.js'
import toast from 'react-hot-toast'
import LoadingSpinner from '../components/LoadingSpinner.jsx'

const schema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Must contain at least one number'),
})

function PasswordHint({ passes, label }) {
  return (
    <span className={`flex items-center gap-1 text-xs ${passes ? 'text-emerald-400' : 'text-gray-500'}`}>
      {passes ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
      {label}
    </span>
  )
}

export default function Register() {
  const { register: registerUser } = useAuth()
  const navigate = useNavigate()
  const [showPwd, setShowPwd] = useState(false)
  const [serverError, setServerError] = useState('')
  const [pwdValue, setPwdValue] = useState('')

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    watch,
  } = useForm({ resolver: zodResolver(schema) })

  const password = watch('password', '')

  const onSubmit = async (data) => {
    setServerError('')
    try {
      await registerUser(data.name, data.email, data.password)
      toast.success('Account created!')
      navigate('/dashboard')
    } catch (err) {
      const msg =
        err?.response?.data?.message ||
        err?.response?.data?.error ||
        'Registration failed. Please try again.'
      setServerError(msg)
    }
  }

  const hints = [
    { passes: (password || '').length >= 8, label: 'At least 8 characters' },
    { passes: /[A-Z]/.test(password || ''), label: 'One uppercase letter' },
    { passes: /[a-z]/.test(password || ''), label: 'One lowercase letter' },
    { passes: /[0-9]/.test(password || ''), label: 'One number' },
  ]

  return (
    <div className="min-h-screen bg-[#0a0f1e] flex items-center justify-center p-4">
      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-5"
        style={{
          backgroundImage:
            'linear-gradient(rgba(0,212,255,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.3) 1px, transparent 1px)',
          backgroundSize: '50px 50px',
        }}
      />

      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-[#00d4ff]/10 border border-[#00d4ff]/30 flex items-center justify-center mb-4 glow-cyan">
            <Shield className="w-9 h-9 text-[#00d4ff]" />
          </div>
          <h1 className="text-2xl font-bold text-white">Create Account</h1>
          <p className="text-gray-500 text-sm mt-1">Join QRShield Sentinel</p>
        </div>

        {/* Card */}
        <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-8">
          {serverError && (
            <div className="flex items-start gap-2 mb-5 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{serverError}</span>
            </div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-5" noValidate>
            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Full name</label>
              <input
                type="text"
                autoComplete="name"
                placeholder="Jane Doe"
                {...register('name')}
                className={`w-full px-4 py-3 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${errors.name ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              {errors.name && <p className="mt-1.5 text-xs text-red-400">{errors.name.message}</p>}
            </div>

            {/* Email */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Email address</label>
              <input
                type="email"
                autoComplete="email"
                placeholder="you@example.com"
                {...register('email')}
                className={`w-full px-4 py-3 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${errors.email ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              {errors.email && <p className="mt-1.5 text-xs text-red-400">{errors.email.message}</p>}
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPwd ? 'text' : 'password'}
                  autoComplete="new-password"
                  placeholder="••••••••"
                  {...register('password')}
                  className={`w-full px-4 py-3 pr-11 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                    transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                    ${errors.password ? 'border-red-500/60' : 'border-[#1f2937]'}`}
                />
                <button
                  type="button"
                  onClick={() => setShowPwd((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {/* Password hints */}
              <div className="mt-2 grid grid-cols-2 gap-1">
                {hints.map((h) => (
                  <PasswordHint key={h.label} passes={h.passes} label={h.label} />
                ))}
              </div>
              {errors.password && (
                <p className="mt-1.5 text-xs text-red-400">{errors.password.message}</p>
              )}
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl
                         bg-[#00d4ff] hover:bg-[#00bde6] active:bg-[#00a8cc]
                         text-[#0a0f1e] font-semibold text-sm
                         transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {isSubmitting && <LoadingSpinner size="sm" className="border-t-[#0a0f1e]" />}
              {isSubmitting ? 'Creating account…' : 'Create account'}
            </button>
          </form>

          <p className="mt-6 text-center text-sm text-gray-500">
            Already have an account?{' '}
            <Link to="/login" className="text-[#00d4ff] hover:text-[#00bde6] font-medium">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
