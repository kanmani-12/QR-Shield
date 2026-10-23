/**
 * Enterprise REST API v1
 *
 * API-key authenticated endpoints for programmatic access.
 * All routes under /api/v1/* require a valid Organisation API key
 * passed via the X-API-Key header.
 *
 * Authentication flow:
 *   1. Client sends X-API-Key header with raw key (e.g. "qrs_abc123…")
 *   2. Middleware hashes the key and looks it up in the APIKey collection
 *   3. If valid, not revoked, and not expired, req.apiKey + req.apiOrg are set
 *
 * Permission checks per route:
 *   - POST /analyze          → requires 'analyze'
 *   - GET  /scans            → requires 'read_scans'
 *   - GET  /trusted-qr       → requires 'manage_trusted_qr'
 *   - POST /trusted-qr       → requires 'manage_trusted_qr'
 *   - GET  /alerts           → requires 'read_alerts'
 */

const express = require('express');
const crypto = require('crypto');
const APIKey = require('../models/APIKey');
const Scan = require('../models/Scan');
const Alert = require('../models/Alert');
const TrustedQR = require('../models/TrustedQR');
const AuditLog = require('../models/AuditLog');
const { analyzeUrl } = require('../services/analysisService');
const { validate, analyzeUrlSchema, paginationSchema, registerQrSchema } = require('../validators');
const { parseAndValidateUrl } = require('../utils/urlParser');
const logger = require('../config/logger');
const { v4: uuidv4 } = require('uuid');

// ── API Key middleware ────────────────────────────────────────────────────────

/**
 * Authenticate request using X-API-Key header.
 * Attaches req.apiKey (the APIKey document) and req.apiOrg (org ObjectId).
 */
async function authenticateApiKey(req, res, next) {
  const rawKey = req.headers['x-api-key'];
  if (!rawKey) {
    return res.status(401).json({
      success: false,
      error: 'API key required. Pass your key in the X-API-Key header.',
      code: 'NO_API_KEY',
    });
  }

  try {
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const apiKey = await APIKey.findOne({ keyHash }).select('+keyHash');

    if (!apiKey) {
      return res.status(401).json({ success: false, error: 'Invalid API key', code: 'INVALID_API_KEY' });
    }
    if (apiKey.isRevoked) {
      return res.status(401).json({ success: false, error: 'API key has been revoked', code: 'KEY_REVOKED' });
    }
    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      return res.status(401).json({ success: false, error: 'API key has expired', code: 'KEY_EXPIRED' });
    }

    // Update usage stats (fire-and-forget)
    APIKey.findByIdAndUpdate(apiKey._id, {
      $inc: { usageCount: 1 },
      lastUsedAt: new Date(),
    }).catch(() => {});

    req.apiKey = apiKey;
    req.apiOrg = apiKey.organisation;
    next();
  } catch (err) {
    logger.error('Enterprise API key auth error:', err);
    next(err);
  }
}

/**
 * Check that the API key has the required permission.
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.apiKey || !req.apiKey.permissions.includes(permission)) {
      return res.status(403).json({
        success: false,
        error: `This API key does not have the '${permission}' permission`,
        code: 'INSUFFICIENT_PERMISSION',
      });
    }
    next();
  };
}

// ── Routers ───────────────────────────────────────────────────────────────────

// POST /api/v1/analyze
const analyzeRouter = express.Router();

analyzeRouter.post(
  '/',
  authenticateApiKey,
  requirePermission('analyze'),
  validate(analyzeUrlSchema),
  async (req, res, next) => {
    try {
      const { url, scanType = 'api', trustedQrId, inspectRedirects } = req.body;

      const scan = new Scan({
        organisation: req.apiOrg,
        user: null,
        submittedUrl: url,
        scanType: 'api',
        status: 'scanning',
        isDemo: false,
      });
      await scan.save();

      const result = await analyzeUrl(url, {
        inspectRedirects,
        scanType: 'api',
        trustedQrId: trustedQrId || null,
        allowOverride: false,
      });

      if (!result.success) {
        scan.status = 'error';
        await scan.save();
        return res.status(400).json({ success: false, error: result.error, urlAnalysis: result.urlAnalysis });
      }

      scan.destinationHostname = result.destinationHostname;
      scan.urlHash = result.urlHash;
      scan.riskLevel = result.riskLevel;
      scan.riskScore = result.riskScore;
      scan.evidence = result.evidence;
      scan.providerResults = result.providerResults;
      scan.redirectChain = result.redirectChain?.hops || [];
      scan.aiExplanation = result.aiExplanation;
      scan.trustedQrMismatch = result.trustedQrMismatch;
      scan.isDemo = result.isDemo;
      scan.status = 'complete';
      await scan.save();

      // High-risk alert for the organisation
      if (result.riskLevel === 'HIGH' && req.apiOrg) {
        const dedupKey = `high_risk:${result.urlHash}:${new Date().toDateString()}:${req.apiOrg}`;
        const existing = await Alert.findOne({ deduplicationKey: dedupKey });
        if (!existing) {
          await Alert.create({
            organisation: req.apiOrg,
            scan: scan._id,
            alertType: 'high_risk_detection',
            severity: 'critical',
            title: 'High Risk URL Detected via API',
            message: `A high-risk URL was submitted via Enterprise API: ${result.destinationHostname || 'unknown host'}`,
            deduplicationKey: dedupKey,
          });
        }
      }

      await AuditLog.create({
        actor: { apiKeyId: req.apiKey._id.toString(), role: 'api' },
        action: 'scan.create.api',
        resourceType: 'scan',
        resourceId: scan._id.toString(),
        outcome: 'success',
      }).catch(() => {});

      res.json({ success: true, scanId: scan._id, ...result });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/v1/scans
const scansRouter = express.Router();

scansRouter.get(
  '/',
  authenticateApiKey,
  requirePermission('read_scans'),
  validate(paginationSchema, 'query'),
  async (req, res, next) => {
    try {
      const { page, limit } = req.query;
      const filter = { organisation: req.apiOrg };

      const [scans, total] = await Promise.all([
        Scan.find(filter)
          .sort({ createdAt: -1 })
          .skip((page - 1) * limit)
          .limit(limit)
          .select('-evidence -providerResults -redirectChain -aiExplanation'),
        Scan.countDocuments(filter),
      ]);

      res.json({
        success: true,
        data: scans,
        pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      });
    } catch (err) {
      next(err);
    }
  }
);

scansRouter.get(
  '/:id',
  authenticateApiKey,
  requirePermission('read_scans'),
  async (req, res, next) => {
    try {
      const scan = await Scan.findById(req.params.id);
      if (!scan) {
        return res.status(404).json({ success: false, error: 'Scan not found', code: 'NOT_FOUND' });
      }
      // Ensure this scan belongs to the org that owns the key
      if (scan.organisation && scan.organisation.toString() !== req.apiOrg.toString()) {
        return res.status(403).json({ success: false, error: 'Access denied', code: 'FORBIDDEN' });
      }
      res.json({ success: true, data: scan });
    } catch (err) {
      next(err);
    }
  }
);

// GET+POST /api/v1/trusted-qr
const trustedQrRouter = express.Router();

trustedQrRouter.get(
  '/',
  authenticateApiKey,
  requirePermission('manage_trusted_qr'),
  validate(paginationSchema, 'query'),
  async (req, res, next) => {
    try {
      const { page, limit } = req.query;
      const filter = { organisation: req.apiOrg, isActive: true };
      const [records, total] = await Promise.all([
        TrustedQR.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
        TrustedQR.countDocuments(filter),
      ]);
      res.json({ success: true, data: records, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
    } catch (err) {
      next(err);
    }
  }
);

trustedQrRouter.post(
  '/',
  authenticateApiKey,
  requirePermission('manage_trusted_qr'),
  validate(registerQrSchema),
  async (req, res, next) => {
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
        organisation: req.apiOrg,
        registeredBy: null,
        label,
        description,
        integrityHash,
        verificationStatus: 'pending',
      });
      await record.save();

      await AuditLog.create({
        actor: { apiKeyId: req.apiKey._id.toString(), role: 'api' },
        action: 'trusted_qr.register.api',
        resourceType: 'trusted_qr',
        resourceId: record._id.toString(),
        outcome: 'success',
      }).catch(() => {});

      res.status(201).json({ success: true, data: record });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/v1/alerts
const alertsRouter = express.Router();

alertsRouter.get(
  '/',
  authenticateApiKey,
  requirePermission('read_alerts'),
  validate(paginationSchema, 'query'),
  async (req, res, next) => {
    try {
      const { page, limit } = req.query;
      const filter = { organisation: req.apiOrg };

      const [alerts, total, unreadCount] = await Promise.all([
        Alert.find(filter)
          .sort({ createdAt: -1 })
          .skip((page - 1) * limit)
          .limit(limit)
          .populate('scan', 'submittedUrl riskLevel destinationHostname createdAt'),
        Alert.countDocuments(filter),
        Alert.countDocuments({ ...filter, isRead: false }),
      ]);

      res.json({
        success: true,
        data: alerts,
        unreadCount,
        pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = { analyzeRouter, scansRouter, trustedQrRouter, alertsRouter };
