const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  actor: {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    userEmail: String,
    role: String,
    apiKeyId: String,
    ip: String,
  },
  action: {
    type: String,
    required: true,
    maxlength: 100,
  },
  resourceType: {
    type: String,
    enum: ['user', 'organisation', 'scan', 'trusted_qr', 'api_key', 'alert', 'policy', 'system'],
    required: true,
  },
  resourceId: String,
  outcome: {
    type: String,
    enum: ['success', 'failure', 'denied'],
    default: 'success',
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
}, {
  timestamps: true,
  // Audit logs are immutable — disable update hooks
});

// TTL index — auto-delete after 365 days (configurable)
auditLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });
auditLogSchema.index({ 'actor.userId': 1, createdAt: -1 });
auditLogSchema.index({ resourceType: 1, resourceId: 1 });
auditLogSchema.index({ action: 1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
