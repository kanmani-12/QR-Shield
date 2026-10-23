const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const TrustedQR = require('../models/TrustedQR');
const AuditLog = require('../models/AuditLog');
const { authenticate } = require('../middleware/auth');
const { validate, registerQrSchema, paginationSchema } = require('../validators');
const { parseAndValidateUrl } = require('../utils/urlParser');

// POST /api/trusted-qr — Register a QR destination
router.post('/', authenticate, validate(registerQrSchema), async (req, res, next) => {
  try {
    const { expectedDestination, label, description } = req.body;

    const urlAnalysis = parseAndValidateUrl(expectedDestination);
    if (!urlAnalysis.isValid) {
      return res.status(400).json({ success: false, error: urlAnalysis.errors[0] || 'Invalid URL' });
    }

    const registrationId = 'QRS-' + uuidv4().toUpperCase().split('-')[0];
    const integrityHash = crypto.createHash('sha256').update(expectedDestination).digest('hex');

    const record = new TrustedQR({
      registrationId,
      expectedDestination,
      expectedHostname: urlAnalysis.hostname,
      organisation: req.user.organisation || null,
      registeredBy: req.user._id,
      label,
      description,
      integrityHash,
      verificationStatus: 'pending',
    });
    await record.save();

    await AuditLog.create({
      actor: { userId: req.user._id, userEmail: req.user.email, role: req.user.role },
      action: 'trusted_qr.register',
      resourceType: 'trusted_qr',
      resourceId: record._id.toString(),
      outcome: 'success',
    });

    res.status(201).json({ success: true, data: record });
  } catch (err) {
    next(err);
  }
});

// GET /api/trusted-qr — List user's/org's registered QRs
router.get('/', authenticate, validate(paginationSchema, 'query'), async (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const filter = req.user.organisation
      ? { $or: [{ registeredBy: req.user._id }, { organisation: req.user.organisation }] }
      : { registeredBy: req.user._id };

    const [records, total] = await Promise.all([
      TrustedQR.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
      TrustedQR.countDocuments(filter),
    ]);

    res.json({ success: true, data: records, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    next(err);
  }
});

// GET /api/trusted-qr/:id
router.get('/:id', authenticate, async (req, res, next) => {
  try {
    const record = await TrustedQR.findById(req.params.id).populate('registeredBy', 'name email');
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    if (record.registeredBy._id.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }
    res.json({ success: true, data: record });
  } catch (err) {
    next(err);
  }
});

// PUT /api/trusted-qr/:id — Update destination
router.put('/:id', authenticate, async (req, res, next) => {
  try {
    const { expectedDestination, label, description, reason } = req.body;
    const record = await TrustedQR.findById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    if (record.registeredBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }

    if (expectedDestination && expectedDestination !== record.expectedDestination) {
      const urlAnalysis = parseAndValidateUrl(expectedDestination);
      if (!urlAnalysis.isValid) return res.status(400).json({ success: false, error: urlAnalysis.errors[0] });

      record.changeHistory.push({
        changedBy: req.user._id,
        previousDestination: record.expectedDestination,
        newDestination: expectedDestination,
        reason: reason || 'No reason provided',
      });
      record.expectedDestination = expectedDestination;
      record.expectedHostname = urlAnalysis.hostname;
      record.integrityHash = crypto.createHash('sha256').update(expectedDestination).digest('hex');
      record.verificationStatus = 'pending';
    }

    if (label) record.label = label;
    if (description !== undefined) record.description = description;
    await record.save();

    await AuditLog.create({
      actor: { userId: req.user._id, userEmail: req.user.email, role: req.user.role },
      action: 'trusted_qr.update',
      resourceType: 'trusted_qr',
      resourceId: record._id.toString(),
      outcome: 'success',
    });

    res.json({ success: true, data: record });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/trusted-qr/:id — Revoke registration
router.delete('/:id', authenticate, async (req, res, next) => {
  try {
    const record = await TrustedQR.findById(req.params.id);
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });
    if (record.registeredBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }
    record.isActive = false;
    record.verificationStatus = 'revoked';
    await record.save();
    res.json({ success: true, message: 'Registration revoked' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
