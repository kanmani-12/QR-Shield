import React from 'react'

const riskConfig = {
  HIGH: {
    label: 'HIGH',
    bg: 'bg-red-500/20',
    text: 'text-red-400',
    border: 'border-red-500/40',
    dot: 'bg-red-400',
  },
  MEDIUM: {
    label: 'MEDIUM',
    bg: 'bg-yellow-500/20',
    text: 'text-yellow-400',
    border: 'border-yellow-500/40',
    dot: 'bg-yellow-400',
  },
  LOW: {
    label: 'LOW',
    bg: 'bg-emerald-500/20',
    text: 'text-emerald-400',
    border: 'border-emerald-500/40',
    dot: 'bg-emerald-400',
  },
  UNKNOWN: {
    label: 'UNKNOWN',
    bg: 'bg-gray-500/20',
    text: 'text-gray-400',
    border: 'border-gray-500/40',
    dot: 'bg-gray-400',
  },
}

export default function RiskBadge({ level, size = 'sm' }) {
  const config = riskConfig[level?.toUpperCase()] || riskConfig.UNKNOWN

  const sizeClasses =
    size === 'lg'
      ? 'px-4 py-2 text-base font-bold tracking-widest'
      : size === 'md'
      ? 'px-3 py-1 text-sm font-semibold tracking-wide'
      : 'px-2 py-0.5 text-xs font-semibold tracking-wide'

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 rounded-full border
        font-mono uppercase
        ${config.bg} ${config.text} ${config.border} ${sizeClasses}
      `}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  )
}
