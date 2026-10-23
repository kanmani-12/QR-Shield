const express = require('express');
const crypto = require('crypto');
const APIKey = require('../models/APIKey');
const AuditLog = require('../models/AuditLog');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// POST /api/api-keys — Create a new API key for the user's organisation
router.post('/', authenticate, requireRole('org_admin'), async (req, res, next) => {
  try {
    if (!req.user.organisation) {
      return res.status(400).json({ success: false, error: 'You must belong to an organisation to create API keys' });
    }
    const { name, permissions, rateLimit, expiresInDays } = req.body;
    const rawKey = APIKey.generateKey();
    const keyHash = APIKey.hashKey(rawKey);
    const keyPrefix = rawKey.slice(0, 12);

    const apiKey = new APIKey({
      organisation: req.user.organisation,
      createdBy: req.user._id,
      name: name || 'Unnamed Key',
      keyHash,
      keyPrefix,
      permissions: permissions || ['analyze', 'read_scans'],
      rateLimit: rateLimit || { requestsPerHour: 100, requestsPerDay: 1000 },
      expiresAt: expiresInDays ? new Date(Date.now() + expiresInDays * 86400000) : null,
    });
    await apiKey.save();

    await AuditLog.create({
      actor: { userId: req.user._id, userEmail: req.user.email, role: req.user.role },
      action: 'api_key.create',
      resourceType: 'api_key',
      resourceId: apiKey._id.toString(),
      outcome: 'success',
    });

    // Return the raw key ONCE — it is never stored or retrievable again
    res.status(201).json({
      success: true,
      message: 'API key created. Copy the key now — it will not be shown again.',
      apiKey: {
        id: apiKey._id,
        name: apiKey.name,
        keyPrefix: apiKey.keyPrefix,
        permissions: apiKey.permissions,
        expiresAt: apiKey.expiresAt,
      },
      rawKey, // Shown only on creation
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/api-keys — List keys for the org (no raw keys)
router.get('/', authenticate, requireRole('org_admin'), async (req, res, next) => {
  try {
    if (!req.user.organisation) return res.json({ success: true, data: [] });
    const keys = await APIKey.find({ organisation: req.user.organisation, isRevoked: false })
      .select('-keyHash')
      .sort({ createdAt: -1 });
    res.json({ success: true, data: keys });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/api-keys/:id — Revoke a key
router.delete('/:id', authenticate, requireRole('org_admin'), async (req, res, next) => {
  try {
    const key = await APIKey.findById(req.params.id);
    if (!key) return res.status(404).json({ success: false, error: 'API key not found' });
    if (key.organisation.toString() !== req.user.organisation?.toString()) {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }
    key.isRevoked = true;
    key.revokedAt = new Date();
    key.revokedBy = req.user._id;
    await key.save();

    await AuditLog.create({
      actor: { userId: req.user._id, userEmail: req.user.email, role: req.user.role },
      action: 'api_key.revoke',
      resourceType: 'api_key',
      resourceId: key._id.toString(),
      outcome: 'success',
    });

    res.json({ success: true, message: 'API key revoked' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
