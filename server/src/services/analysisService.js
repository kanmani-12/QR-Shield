/**
 * Main URL Analysis Service
 *
 * Orchestrates URL validation, threat-intelligence checks, redirect inspection,
 * risk scoring, and AI explanation generation.
 */
const crypto = require('crypto');
const { parseAndValidateUrl, detectLookalike } = require('../utils/urlParser');
const { validateUrlForScanning } = require('../utils/ssrfProtection');
const { calculateRisk, getRecommendedAction } = require('./riskEngine');
const demoMode = require('./demoMode');
const gsbAdapter = require('./threatIntel/googleSafeBrowsing');
const vtAdapter = require('./threatIntel/virusTotal');
const aiService = require('./aiService');
const logger = require('../config/logger');

const providers = [gsbAdapter, vtAdapter];

/**
 * Run the full URL analysis pipeline.
 *
 * @param {string} rawUrl
 * @param {object} options
 * @param {boolean} options.inspectRedirects - Whether to run redirect inspection (default: true)
 * @param {string} options.scanType - The scan type (qr_upload, url_direct, etc.)
 * @param {string|null} options.trustedQrId - ID of associated TrustedQR record
 * @returns {Promise<object>} Analysis result
 */
async function analyzeUrl(rawUrl, options = {}) {
  const {
    inspectRedirects = true,
    scanType = 'url_direct',
    trustedQrId = null,
    allowOverride = false,
  } = options;

  const startTime = Date.now();

  // ── Step 1: URL parsing and structure analysis ────────────────────────────
  const urlAnalysis = parseAndValidateUrl(rawUrl);
  const lookalike = urlAnalysis.isValid && urlAnalysis.hostname
    ? detectLookalike(urlAnalysis.hostname)
    : { detected: false };

  if (!urlAnalysis.isValid) {
    return {
      success: false,
      error: urlAnalysis.errors[0] || 'Invalid URL',
      urlAnalysis,
    };
  }

  // ── Step 2: SSRF check before any outbound request ───────────────────────
  const ssrfCheck = await validateUrlForScanning(rawUrl, { resolveHostname: true });
  if (!ssrfCheck.valid) {
    // Still return analysis, but mark as error for scanning
    return {
      success: true,
      scanType,
      submittedUrl: rawUrl,
      destinationHostname: urlAnalysis.hostname,
      urlHash: crypto.createHash('sha256').update(rawUrl.toLowerCase().trim()).digest('hex'),
      urlAnalysis,
      ssrfBlocked: true,
      ssrfReason: ssrfCheck.reason,
      riskLevel: 'HIGH',
      riskScore: 100,
      evidence: [{
        factor: 'URL points to a non-public address',
        severity: 'high',
        description: ssrfCheck.reason,
        source: 'ssrf_protection',
      }],
      providerResults: [],
      redirectChain: null,
      recommendation: getRecommendedAction('HIGH', false),
      aiExplanation: null,
      durationMs: Date.now() - startTime,
    };
  }

  // ── Step 3: Threat intelligence checks ───────────────────────────────────
  let providerResults;
  let isDemo = false;

  if (demoMode.isActive()) {
    const demoResult = demoMode.getDemoResult(rawUrl);
    providerResults = demoResult.providers;
    isDemo = true;
  } else {
    // Run all configured providers in parallel
    providerResults = await Promise.all(
      providers.map(p => p.check(rawUrl).catch(err => ({
        provider: p.name,
        status: 'unavailable',
        details: `Provider error: ${err.message}`,
        checkedAt: new Date(),
      })))
    );
  }

  // ── Step 4: Redirect inspection (backend-only, SSRF-protected) ───────────
  let redirectChain = null;
  if (inspectRedirects && !isDemo && process.env.ISOLATED_SCANNER_ENABLED === 'true') {
    try {
      const { inspectRedirects: inspect } = require('./redirectInspector');
      redirectChain = await inspect(rawUrl);
    } catch (err) {
      logger.warn(`Redirect inspection failed: ${err.message}`);
      redirectChain = { available: false, reason: err.message };
    }
  }

  // ── Step 5: TrustedQR mismatch check ─────────────────────────────────────
  let trustedQrMismatch = false;
  if (trustedQrId) {
    const TrustedQR = require('../models/TrustedQR');
    const record = await TrustedQR.findById(trustedQrId);
    if (record && record.isActive) {
      const expectedHost = record.expectedHostname.toLowerCase();
      const actualHost = (urlAnalysis.hostname || '').toLowerCase();
      if (expectedHost !== actualHost) {
        trustedQrMismatch = true;
        await TrustedQR.findByIdAndUpdate(trustedQrId, {
          $inc: { mismatchCount: 1 },
          verificationStatus: 'mismatch_detected',
          lastScannedAt: new Date(),
        });
      } else {
        await TrustedQR.findByIdAndUpdate(trustedQrId, { lastScannedAt: new Date() });
      }
    }
  }

  // ── Step 6: Risk scoring ──────────────────────────────────────────────────
  const demoEvidence = isDemo ? demoMode.getDemoResult(rawUrl).evidence : [];
  const { riskLevel, riskScore, evidence, allProvidersUnavailable } = calculateRisk({
    urlAnalysis,
    providerResults: isDemo ? [] : providerResults,
    redirectChain,
    trustedQrMismatch,
    lookalike,
  });

  const finalEvidence = [...evidence, ...demoEvidence];

  // ── Step 7: AI explanation (optional) ────────────────────────────────────
  let aiExplanation = null;
  if (!isDemo) {
    aiExplanation = await aiService.explain({
      url: rawUrl,
      hostname: urlAnalysis.hostname,
      riskLevel,
      riskScore,
      evidence: finalEvidence,
      providerResults,
    }).catch(() => null);
  }

  // ── Step 8: Recommended action ────────────────────────────────────────────
  const recommendation = getRecommendedAction(riskLevel, allowOverride);

  return {
    success: true,
    scanType,
    submittedUrl: rawUrl,
    destinationHostname: urlAnalysis.hostname,
    urlHash: crypto.createHash('sha256').update(rawUrl.toLowerCase().trim()).digest('hex'),
    urlAnalysis,
    riskLevel,
    riskScore,
    evidence: finalEvidence,
    providerResults,
    redirectChain,
    trustedQrMismatch,
    recommendation,
    aiExplanation,
    isDemo,
    demoWarning: isDemo ? 'DEMO MODE: Results are simulated. Configure threat-intelligence API keys for real analysis.' : null,
    allProvidersUnavailable: !isDemo && allProvidersUnavailable,
    durationMs: Date.now() - startTime,
  };
}

module.exports = { analyzeUrl };
