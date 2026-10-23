const mongoose = require('mongoose');

const providerResultSchema = new mongoose.Schema({
  provider: { type: String, required: true },
  status: { type: String, enum: ['clean', 'malicious', 'suspicious', 'unavailable', 'demo'], required: true },
  categories: [String],
  details: String,
  checkedAt: { type: Date, default: Date.now },
}, { _id: false });

const redirectHopSchema = new mongoose.Schema({
  url: String,
  hostname: String,
  statusCode: Number,
  suspicious: Boolean,
}, { _id: false });

const riskEvidenceSchema = new mongoose.Schema({
  factor: { type: String, required: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'info'] },
  description: String,
}, { _id: false });

const scanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  organisation: { type: mongoose.Schema.Types.ObjectId, ref: 'Organisation', default: null },

  // URL data — store hostname only in privacy-minimised mode
  submittedUrl: {
    type: String,
    required: true,
    maxlength: 2048,
  },
  destinationHostname: String,
  urlHash: String, // SHA-256 of normalised URL for deduplication

  scanType: {
    type: String,
    enum: ['qr_upload', 'qr_camera', 'url_direct', 'file_link', 'api', 'extension'],
    required: true,
  },

  status: {
    type: String,
    enum: ['pending', 'scanning', 'complete', 'error'],
    default: 'pending',
  },

  riskLevel: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN'],
    default: 'UNKNOWN',
  },
  riskScore: { type: Number, min: 0, max: 100, default: null },

  evidence: [riskEvidenceSchema],
  providerResults: [providerResultSchema],
  redirectChain: [redirectHopSchema],

  aiExplanation: {
    en: String,
    ta: String,
  },

  trustedQrMismatch: { type: Boolean, default: false },
  trustedQrRegistryId: { type: mongoose.Schema.Types.ObjectId, ref: 'TrustedQR', default: null },

  // Demo mode scan
  isDemo: { type: Boolean, default: false },

  // High-risk override
  overrideAllowed: { type: Boolean, default: false },
  overrideAcknowledgedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  overrideAcknowledgedAt: Date,
}, {
  timestamps: true,
});

scanSchema.index({ user: 1, createdAt: -1 });
scanSchema.index({ organisation: 1, createdAt: -1 });
scanSchema.index({ riskLevel: 1 });
scanSchema.index({ destinationHostname: 1 });
scanSchema.index({ urlHash: 1 });
scanSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Scan', scanSchema);
