const mongoose = require('mongoose');
const crypto = require('crypto');

const apiKeySchema = new mongoose.Schema({
  organisation: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organisation',
    required: true,
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
  },
  keyHash: {
    type: String,
    required: true,
    select: false, // Never return in queries
  },
  keyPrefix: {
    type: String,
    required: true, // First 8 chars for identification (e.g., "qrs_abcd")
  },
  permissions: {
    type: [String],
    enum: ['analyze', 'read_scans', 'manage_trusted_qr', 'read_alerts'],
    default: ['analyze', 'read_scans'],
  },
  rateLimit: {
    requestsPerHour: { type: Number, default: 100 },
    requestsPerDay: { type: Number, default: 1000 },
  },
  usageCount: { type: Number, default: 0 },
  lastUsedAt: Date,
  expiresAt: { type: Date, default: null },
  isRevoked: { type: Boolean, default: false },
  revokedAt: Date,
  revokedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, {
  timestamps: true,
});

// Hash a raw API key
apiKeySchema.statics.hashKey = function (rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
};

// Generate a new raw API key (call before save, store hash only)
apiKeySchema.statics.generateKey = function () {
  const rawKey = 'qrs_' + crypto.randomBytes(32).toString('hex');
  return rawKey;
};

apiKeySchema.index({ organisation: 1 });
apiKeySchema.index({ keyPrefix: 1 });

module.exports = mongoose.model('APIKey', apiKeySchema);
