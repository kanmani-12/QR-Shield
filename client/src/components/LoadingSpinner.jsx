import React from 'react'

const sizeClasses = {
  sm: 'w-4 h-4 border-2',
  md: 'w-8 h-8 border-2',
  lg: 'w-12 h-12 border-3',
  xl: 'w-16 h-16 border-4',
}

export default function LoadingSpinner({ size = 'md', className = '' }) {
  return (
    <div
      className={`
        rounded-full animate-spin
        border-transparent border-t-[#00d4ff]
        ${sizeClasses[size]}
        ${className}
      `}
      style={{ borderStyle: 'solid' }}
    />
  )
}
