import React, { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  User,
  Lock,
  Bell,
  Save,
  AlertCircle,
  Check,
  Eye,
  EyeOff,
  Mail,
  Calendar,
  Shield,
} from 'lucide-react'
import { useAuth } from '../hooks/useAuth.js'
import apiClient from '../api/client.js'
import LoadingSpinner from '../components/LoadingSpinner.jsx'
import toast from 'react-hot-toast'

const profileSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  languagePreference: z.enum(['en', 'ta']),
})

const pwdSchema = z
  .object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: z
      .string()
      .min(8, 'Min 8 characters')
      .regex(/[A-Z]/, 'Must contain uppercase')
      .regex(/[a-z]/, 'Must contain lowercase')
      .regex(/[0-9]/, 'Must contain a number'),
    confirmPassword: z.string(),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  })

function SectionCard({ title, icon: Icon, children }) {
  return (
    <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
      <div className="flex items-center gap-2 mb-5">
        <Icon className="w-5 h-5 text-[#00d4ff]" />
        <h2 className="text-base font-semibold text-gray-200">{title}</h2>
      </div>
      {children}
    </div>
  )
}

export default function Profile() {
  const { user, setUser } = useAuth()
  const [profileData, setProfileData] = useState(null)
  const [loadingProfile, setLoadingProfile] = useState(true)
  const [profileError, setProfileError] = useState('')
  const [pwdError, setPwdError] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [notifPrefs, setNotifPrefs] = useState({ email: true, inApp: true, highRiskOnly: false })
  const [savingNotif, setSavingNotif] = useState(false)

  const {
    register: regProfile,
    handleSubmit: handleProfile,
    reset: resetProfile,
    formState: { errors: profileErrors, isSubmitting: savingProfile },
  } = useForm({ resolver: zodResolver(profileSchema), defaultValues: { name: '', languagePreference: 'en' } })

  const {
    register: regPwd,
    handleSubmit: handlePwd,
    reset: resetPwd,
    formState: { errors: pwdErrors, isSubmitting: savingPwd },
  } = useForm({ resolver: zodResolver(pwdSchema) })

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const res = await apiClient.get('/api/users/profile')
        const data = res.data?.user ?? res.data?.data ?? res.data
        setProfileData(data)
        resetProfile({
          name: data?.name || '',
          languagePreference: data?.languagePreference || 'en',
        })
        if (data?.notificationPreferences) {
          setNotifPrefs(data.notificationPreferences)
        }
      } catch {
        setProfileError('Failed to load profile')
      } finally {
        setLoadingProfile(false)
      }
    }
    fetchProfile()
  }, [resetProfile])

  const onSaveProfile = async (data) => {
    setProfileError('')
    try {
      const res = await apiClient.patch('/api/users/profile', data)
      const updated = res.data?.user ?? res.data?.data ?? res.data
      setProfileData(updated)
      if (setUser) setUser((u) => ({ ...u, name: data.name }))
      toast.success('Profile updated')
    } catch (err) {
      setProfileError(err?.response?.data?.message || 'Failed to update profile')
    }
  }

  const onChangePassword = async (data) => {
    setPwdError('')
    try {
      await apiClient.post('/api/users/change-password', {
        currentPassword: data.currentPassword,
        newPassword: data.newPassword,
      })
      resetPwd()
      toast.success('Password changed successfully')
    } catch (err) {
      setPwdError(err?.response?.data?.message || 'Failed to change password')
    }
  }

  const onSaveNotifPrefs = async () => {
    setSavingNotif(true)
    try {
      await apiClient.patch('/api/users/profile', { notificationPreferences: notifPrefs })
      toast.success('Notification preferences saved')
    } catch {
      toast.error('Failed to save preferences')
    } finally {
      setSavingNotif(false)
    }
  }

  if (loadingProfile) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <LoadingSpinner size="xl" />
      </div>
    )
  }

  const display = profileData || user || {}

  return (
    <div className="max-w-2xl mx-auto space-y-6 fade-in-up">
      <div>
        <h1 className="text-2xl font-bold text-white">Profile Settings</h1>
        <p className="text-gray-500 text-sm mt-1">Manage your account and preferences</p>
      </div>

      {/* Account info card */}
      <div className="bg-[#111827] border border-[#1f2937] rounded-2xl p-6">
        <div className="flex items-center gap-4">
          <div className="w-16 h-16 rounded-2xl bg-[#00d4ff]/10 border border-[#00d4ff]/30 flex items-center justify-center flex-shrink-0">
            <span className="text-2xl font-bold text-[#00d4ff]">
              {(display.name || display.email || 'U')[0].toUpperCase()}
            </span>
          </div>
          <div>
            <p className="text-lg font-semibold text-white">{display.name || 'User'}</p>
            <div className="flex items-center gap-1.5 text-sm text-gray-500 mt-0.5">
              <Mail className="w-3.5 h-3.5" />
              {display.email}
            </div>
            <div className="flex items-center gap-3 mt-1.5">
              <div className="flex items-center gap-1 text-xs text-gray-600">
                <Shield className="w-3 h-3" />
                <span className="capitalize">{display.role || 'user'}</span>
              </div>
              {display.createdAt && (
                <div className="flex items-center gap-1 text-xs text-gray-600">
                  <Calendar className="w-3 h-3" />
                  Joined {new Date(display.createdAt).toLocaleDateString('en-US', { dateStyle: 'medium' })}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Edit profile */}
      <SectionCard title="Edit Profile" icon={User}>
        {profileError && (
          <div className="flex items-start gap-2 mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            {profileError}
          </div>
        )}
        <form onSubmit={handleProfile(onSaveProfile)} className="space-y-4" noValidate>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Display name</label>
            <input
              type="text"
              {...regProfile('name')}
              className={`w-full px-4 py-3 rounded-xl bg-[#0d1426] border text-white text-sm
                transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                ${profileErrors.name ? 'border-red-500/60' : 'border-[#1f2937]'}`}
            />
            {profileErrors.name && (
              <p className="mt-1.5 text-xs text-red-400">{profileErrors.name.message}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Language preference</label>
            <select
              {...regProfile('languagePreference')}
              className="w-full px-4 py-3 rounded-xl bg-[#0d1426] border border-[#1f2937] text-white text-sm
                         focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30 transition-colors"
            >
              <option value="en">English</option>
              <option value="ta">Tamil (தமிழ்)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={savingProfile}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6]
                       text-[#0a0f1e] font-semibold text-sm transition-colors disabled:opacity-60"
          >
            {savingProfile ? <LoadingSpinner size="sm" className="border-t-[#0a0f1e]" /> : <Save className="w-4 h-4" />}
            Save Changes
          </button>
        </form>
      </SectionCard>

      {/* Change password */}
      <SectionCard title="Change Password" icon={Lock}>
        {pwdError && (
          <div className="flex items-start gap-2 mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            {pwdError}
          </div>
        )}
        <form onSubmit={handlePwd(onChangePassword)} className="space-y-4" noValidate>
          {/* Current password */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Current password</label>
            <div className="relative">
              <input
                type={showCurrent ? 'text' : 'password'}
                {...regPwd('currentPassword')}
                placeholder="••••••••"
                className={`w-full px-4 py-3 pr-10 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${pwdErrors.currentPassword ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              <button
                type="button"
                onClick={() => setShowCurrent((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              >
                {showCurrent ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {pwdErrors.currentPassword && (
              <p className="mt-1.5 text-xs text-red-400">{pwdErrors.currentPassword.message}</p>
            )}
          </div>

          {/* New password */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">New password</label>
            <div className="relative">
              <input
                type={showNew ? 'text' : 'password'}
                {...regPwd('newPassword')}
                placeholder="••••••••"
                className={`w-full px-4 py-3 pr-10 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${pwdErrors.newPassword ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              <button
                type="button"
                onClick={() => setShowNew((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              >
                {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {pwdErrors.newPassword && (
              <p className="mt-1.5 text-xs text-red-400">{pwdErrors.newPassword.message}</p>
            )}
          </div>

          {/* Confirm password */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Confirm new password</label>
            <div className="relative">
              <input
                type={showConfirm ? 'text' : 'password'}
                {...regPwd('confirmPassword')}
                placeholder="••••••••"
                className={`w-full px-4 py-3 pr-10 rounded-xl bg-[#0d1426] border text-white placeholder-gray-600 text-sm
                  transition-colors focus:border-[#00d4ff]/60 focus:ring-1 focus:ring-[#00d4ff]/30
                  ${pwdErrors.confirmPassword ? 'border-red-500/60' : 'border-[#1f2937]'}`}
              />
              <button
                type="button"
                onClick={() => setShowConfirm((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              >
                {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {pwdErrors.confirmPassword && (
              <p className="mt-1.5 text-xs text-red-400">{pwdErrors.confirmPassword.message}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={savingPwd}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6]
                       text-[#0a0f1e] font-semibold text-sm transition-colors disabled:opacity-60"
          >
            {savingPwd ? <LoadingSpinner size="sm" className="border-t-[#0a0f1e]" /> : <Lock className="w-4 h-4" />}
            Change Password
          </button>
        </form>
      </SectionCard>

      {/* Notification preferences */}
      <SectionCard title="Notification Preferences" icon={Bell}>
        <div className="space-y-4">
          {[
            { key: 'email', label: 'Email notifications', desc: 'Receive alerts via email' },
            { key: 'inApp', label: 'In-app notifications', desc: 'Show alerts in the dashboard' },
            { key: 'highRiskOnly', label: 'High risk alerts only', desc: 'Only notify for HIGH risk threats' },
          ].map(({ key, label, desc }) => (
            <div key={key} className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-300">{label}</p>
                <p className="text-xs text-gray-600">{desc}</p>
              </div>
              <button
                onClick={() => setNotifPrefs((p) => ({ ...p, [key]: !p[key] }))}
                className={`relative w-11 h-6 rounded-full transition-colors ${
                  notifPrefs[key] ? 'bg-[#00d4ff]' : 'bg-[#1f2937]'
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow-sm transition-transform ${
                    notifPrefs[key] ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          ))}

          <button
            onClick={onSaveNotifPrefs}
            disabled={savingNotif}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#00d4ff] hover:bg-[#00bde6]
                       text-[#0a0f1e] font-semibold text-sm transition-colors disabled:opacity-60 mt-2"
          >
            {savingNotif ? <LoadingSpinner size="sm" className="border-t-[#0a0f1e]" /> : <Save className="w-4 h-4" />}
            Save Preferences
          </button>
        </div>
      </SectionCard>
    </div>
  )
}
