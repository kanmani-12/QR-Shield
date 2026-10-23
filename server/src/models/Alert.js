const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  organisation: { type: mongoose.Schema.Types.ObjectId, ref: 'Organisation', default: null },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  scan: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', default: null },
  alertType: {
    type: String,
    enum: [
      'high_risk_detection',
      'trusted_qr_mismatch',
      'repeated_threat',
      'quota_exceeded',
      'provider_unavailable',
      'system',
    ],
    required: true,
  },
  severity: {
    type: String,
    enum: ['info', 'warning', 'critical'],
    default: 'warning',
  },
  title: { type: String, required: true, maxlength: 200 },
  message: { type: String, required: true, maxlength: 1000 },
  isRead: { type: Boolean, default: false },
  readAt: Date,
  isEmailSent: { type: Boolean, default: false },
  deduplicationKey: { type: String }, // Prevent duplicate alerts
}, {
  timestamps: true,
});

alertSchema.index({ organisation: 1, isRead: 1, createdAt: -1 });
alertSchema.index({ user: 1, isRead: 1, createdAt: -1 });
alertSchema.index({ deduplicationKey: 1 }, { sparse: true });

module.exports = mongoose.model('Alert', alertSchema);
