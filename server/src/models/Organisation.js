const mongoose = require('mongoose');

const memberSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  role: { type: String, enum: ['member', 'admin', 'owner'], default: 'member' },
  joinedAt: { type: Date, default: Date.now },
}, { _id: false });

const policySchema = new mongoose.Schema({
  blockHighRisk: { type: Boolean, default: true },
  warnMediumRisk: { type: Boolean, default: true },
  allowHighRiskOverride: { type: Boolean, default: false },
  requireScanForExternalUrls: { type: Boolean, default: false },
  retentionDays: { type: Number, default: 90, min: 1, max: 365 },
  maxScansPerDay: { type: Number, default: 100 },
}, { _id: false });

const organisationSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Organisation name is required'],
    trim: true,
    maxlength: [200, 'Name must be at most 200 characters'],
  },
  slug: {
    type: String,
    unique: true,
    lowercase: true,
    trim: true,
  },
  verifiedDomain: {
    type: String,
    lowercase: true,
    trim: true,
    default: null,
  },
  members: [memberSchema],
  policies: {
    type: policySchema,
    default: () => ({}),
  },
  plan: {
    type: String,
    enum: ['free', 'pro', 'enterprise', 'development'],
    default: 'free',
  },
  scanQuotaUsed: { type: Number, default: 0 },
  scanQuotaResetAt: { type: Date, default: Date.now },
  status: {
    type: String,
    enum: ['active', 'suspended'],
    default: 'active',
  },
  contactEmail: String,
}, {
  timestamps: true,
});

// Auto-generate slug from name
organisationSchema.pre('validate', function (next) {
  if (this.isNew && this.name && !this.slug) {
    this.slug = this.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  }
  next();
});

organisationSchema.index({ 'members.user': 1 });

module.exports = mongoose.model('Organisation', organisationSchema);
