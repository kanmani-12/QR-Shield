const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const Alert = require('../models/Alert');
const AuditLog = require('../models/AuditLog');
const { analyzeUrl } = require('../services/analysisService');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { scanRateLimiter } = require('../middleware/rateLimiter');
const { validate, analyzeUrlSchema, paginationSchema } = require('../validators');

// POST /api/scans — Submit URL for analysis
router.post('/', optionalAuth, scanRateLimiter, validate(analyzeUrlSchema), async (req, res, next) => {
  try {
    const { url, scanType, trustedQrId, inspectRedirects } = req.body;

    // Create pending scan record
    const scan = new Scan({
      user: req.user?._id || null,
      organisation: req.user?.organisation || null,
      submittedUrl: url,
      scanType,
      status: 'scanning',
      isDemo: false,
    });
    await scan.save();

    // Run analysis
    const result = await analyzeUrl(url, {
      inspectRedirects,
      scanType,
      trustedQrId: trustedQrId || null,
      allowOverride: false,
    });

    if (!result.success) {
      scan.status = 'error';
      await scan.save();
      return res.status(400).json({
        success: false,
        error: result.error,
        urlAnalysis: result.urlAnalysis,
      });
    }

    // Update scan record with results
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

    // Create alert for high-risk detections
    if (result.riskLevel === 'HIGH' && (req.user?.organisation || req.user?._id)) {
      const dedupKey = `high_risk:${result.urlHash}:${new Date().toDateString()}`;
      const existing = await Alert.findOne({ deduplicationKey: dedupKey });
      if (!existing) {
        await Alert.create({
          organisation: req.user?.organisation || null,
          user: req.user?._id || null,
          scan: scan._id,
          alertType: 'high_risk_detection',
          severity: 'critical',
          title: 'High Risk URL Detected',
          message: `A high-risk URL was scanned: ${result.destinationHostname || 'unknown host'}`,
          deduplicationKey: dedupKey,
        });
      }
    }

    res.json({
      success: true,
      scanId: scan._id,
      ...result,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/scans — Get user's scan history
router.get('/', authenticate, validate(paginationSchema, 'query'), async (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const skip = (page - 1) * limit;

    const filter = { user: req.user._id };
    if (req.user.role !== 'admin' && req.user.role !== 'org_admin') {
      filter.user = req.user._id;
    }

    const [scans, total] = await Promise.all([
      Scan.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('-evidence -providerResults -redirectChain -aiExplanation'),
      Scan.countDocuments(filter),
    ]);

    res.json({
      success: true,
      data: scans,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/scans/:id — Get scan details
router.get('/:id', optionalAuth, async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ success: false, error: 'Scan not found', code: 'NOT_FOUND' });
    }

    // Users can only see their own scans; unauthenticated users can see their session's scans
    if (req.user && scan.user && scan.user.toString() !== req.user._id.toString()) {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, error: 'Access denied', code: 'FORBIDDEN' });
      }
    }

    res.json({ success: true, data: scan });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/scans/:id — Delete a scan (own scans only)
router.delete('/:id', authenticate, async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ success: false, error: 'Scan not found' });
    }
    if (scan.user?.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }
    await scan.deleteOne();
    res.json({ success: true, message: 'Scan deleted' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
