const mongoose = require('mongoose');

const changeHistorySchema = new mongoose.Schema({
  changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  previousDestination: String,
  newDestination: String,
  reason: String,
  changedAt: { type: Date, default: Date.now },
}, { _id: false });

const trustedQrSchema = new mongoose.Schema({
  registrationId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  expectedDestination: {
    type: String,
    required: [true, 'Expected destination URL is required'],
    maxlength: 2048,
  },
  expectedHostname: {
    type: String,
    required: true,
  },
  organisation: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organisation',
    default: null,
  },
  registeredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  label: {
    type: String,
    trim: true,
    maxlength: 200,
  },
  description: {
    type: String,
    maxlength: 1000,
  },
  verificationStatus: {
    type: String,
    enum: ['pending', 'verified', 'revoked', 'mismatch_detected'],
    default: 'pending',
  },
  integrityHash: String, // Hash of the expected destination for tamper detection
  changeHistory: [changeHistorySchema],
  lastScannedAt: Date,
  lastScanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan' },
  mismatchCount: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
}, {
  timestamps: true,
});

trustedQrSchema.index({ organisation: 1 });
trustedQrSchema.index({ registeredBy: 1 });
trustedQrSchema.index({ expectedHostname: 1 });

module.exports = mongoose.model('TrustedQR', trustedQrSchema);
