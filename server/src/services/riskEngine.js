/**
 * Risk Scoring Engine
 *
 * Aggregates evidence from URL analysis, threat-intelligence providers,
 * and redirect chain inspection to produce an evidence-based risk classification.
 *
 * Output levels: LOW | MEDIUM | HIGH | UNKNOWN
 *
 * This engine distinguishes:
 * - Confirmed malicious matches (from threat-intelligence providers)
 * - Heuristic indicators (from URL structure analysis)
 * - Insufficient evidence (UNKNOWN)
 *
 * HTTPS and SSL certificates alone do not reduce risk.
 * A clean provider result does not guarantee safety.
 */

const RISK_LEVELS = { LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH', UNKNOWN: 'UNKNOWN' };

/**
 * Score weights for evidence types.
 * Confirmed malicious = immediate HIGH.
 */
const WEIGHTS = {
  // Provider results
  provider_malicious: 100,       // Confirmed malicious by a threat-intel provider
  provider_suspicious: 50,       // Suspicious (multiple engines)

  // URL structure
  executable_extension: 40,
  user_info_in_url: 35,
  ip_literal: 20,
  punycode_domain: 25,
  shortened_url: 15,
  suspicious_tld: 15,
  percent_encoding: 10,
  non_standard_port: 8,
  excessive_subdomains: 8,
  lookalike_domain: 35,

  // Redirect chain
  redirect_mismatch: 30,
  redirect_to_ip: 25,
  excessive_redirects: 20,

  // Trusted QR
  trusted_qr_mismatch: 60,
};

/**
 * Calculate risk score and level from all evidence sources.
 *
 * @param {object} options
 * @param {object} options.urlAnalysis - Result from parseAndValidateUrl
 * @param {array} options.providerResults - Results from threat-intel providers
 * @param {object} options.redirectChain - Redirect chain analysis
 * @param {boolean} options.trustedQrMismatch - Whether TrustedQR mismatch was detected
 * @param {object} options.lookalike - Lookalike domain detection result
 * @returns {{ riskLevel: string, riskScore: number, evidence: array }}
 */
function calculateRisk({ urlAnalysis, providerResults = [], redirectChain = null, trustedQrMismatch = false, lookalike = null }) {
  const evidence = [];
  let score = 0;
  let confirmedMalicious = false;
  let allProvidersUnavailable = true;

  // ── Provider results ───────────────────────────────────────────────────────
  for (const result of providerResults) {
    if (result.status === 'malicious') {
      confirmedMalicious = true;
      allProvidersUnavailable = false;
      const w = WEIGHTS.provider_malicious;
      score += w;
      evidence.push({
        factor: `Malicious URL detected by ${result.provider}`,
        severity: 'high',
        description: result.details || `${result.provider} confirmed this URL as malicious.`,
        weight: w,
        source: 'threat_intelligence',
      });
    } else if (result.status === 'suspicious') {
      allProvidersUnavailable = false;
      const w = WEIGHTS.provider_suspicious;
      score += w;
      evidence.push({
        factor: `Suspicious URL flagged by ${result.provider}`,
        severity: 'medium',
        description: result.details || `${result.provider} flagged this URL as suspicious.`,
        weight: w,
        source: 'threat_intelligence',
      });
    } else if (result.status === 'clean') {
      allProvidersUnavailable = false;
      evidence.push({
        factor: `${result.provider}: No threats found`,
        severity: 'info',
        description: `${result.provider} did not detect any known threats. This does not guarantee the URL is safe.`,
        weight: 0,
        source: 'threat_intelligence',
      });
    } else if (result.status === 'demo') {
      // Demo results — treat as UNKNOWN contribution
    }
    // unavailable — don't count as safe
  }

  // ── URL structure flags ────────────────────────────────────────────────────
  if (urlAnalysis && urlAnalysis.flags) {
    for (const flag of urlAnalysis.flags) {
      const w = WEIGHTS[flag.type] || 5;
      score += w;
      evidence.push({
        factor: `URL structure: ${flag.type.replace(/_/g, ' ')}`,
        severity: flag.severity,
        description: flag.message,
        weight: w,
        source: 'url_analysis',
      });
    }
  }

  // ── Lookalike domain ───────────────────────────────────────────────────────
  if (lookalike && lookalike.detected) {
    const w = WEIGHTS.lookalike_domain;
    score += w;
    evidence.push({
      factor: 'Potential brand impersonation',
      severity: 'high',
      description: lookalike.message,
      weight: w,
      source: 'url_analysis',
    });
  }

  // ── Redirect chain ─────────────────────────────────────────────────────────
  if (redirectChain) {
    if (redirectChain.mismatch) {
      const w = WEIGHTS.redirect_mismatch;
      score += w;
      evidence.push({
        factor: 'Redirect destination mismatch',
        severity: 'high',
        description: redirectChain.mismatchReason || 'The URL redirects to an unexpected destination',
        weight: w,
        source: 'redirect_analysis',
      });
    }
    if (redirectChain.hasIpDestination) {
      const w = WEIGHTS.redirect_to_ip;
      score += w;
      evidence.push({
        factor: 'Redirect chain leads to an IP address',
        severity: 'medium',
        description: 'The URL redirects to a raw IP address, which is uncommon for legitimate services',
        weight: w,
        source: 'redirect_analysis',
      });
    }
    if (redirectChain.count > 3) {
      const w = WEIGHTS.excessive_redirects;
      score += w;
      evidence.push({
        factor: 'Excessive redirects',
        severity: 'medium',
        description: `URL chain contains ${redirectChain.count} redirects, which may be used to obscure the final destination`,
        weight: w,
        source: 'redirect_analysis',
      });
    }
  }

  // ── Trusted QR mismatch ───────────────────────────────────────────────────
  if (trustedQrMismatch) {
    const w = WEIGHTS.trusted_qr_mismatch;
    score += w;
    confirmedMalicious = true; // Mismatch is treated as high-confidence threat
    evidence.push({
      factor: 'Trusted QR destination mismatch',
      severity: 'high',
      description: 'This QR code is registered with a known expected destination, but the scanned destination does not match. This may indicate the QR sticker has been replaced.',
      weight: w,
      source: 'trusted_qr',
    });
  }

  // ── Determine risk level ──────────────────────────────────────────────────
  let riskLevel;
  const cappedScore = Math.min(score, 100);

  if (confirmedMalicious || score >= 80) {
    riskLevel = RISK_LEVELS.HIGH;
  } else if (score >= 35) {
    riskLevel = RISK_LEVELS.MEDIUM;
  } else if (score >= 0 && !allProvidersUnavailable) {
    riskLevel = RISK_LEVELS.LOW;
  } else {
    riskLevel = RISK_LEVELS.UNKNOWN;
  }

  // If all providers were unavailable and no strong URL signals, stay UNKNOWN
  if (allProvidersUnavailable && score < 35) {
    riskLevel = score >= 20 ? RISK_LEVELS.MEDIUM : RISK_LEVELS.UNKNOWN;
  }

  return {
    riskLevel,
    riskScore: cappedScore,
    evidence,
    allProvidersUnavailable,
  };
}

/**
 * Generate recommended action based on risk level.
 */
function getRecommendedAction(riskLevel, allowOverride = false) {
  switch (riskLevel) {
    case RISK_LEVELS.HIGH:
      return {
        action: 'block',
        canProceed: allowOverride,
        requiresAcknowledgement: allowOverride,
        messageEn: 'This URL has been blocked due to high risk. Do not proceed.',
        messageTa: 'இந்த URL அதிக ஆபத்து காரணமாக தடுக்கப்பட்டுள்ளது. தொடர வேண்டாம்.',
      };
    case RISK_LEVELS.MEDIUM:
      return {
        action: 'warn',
        canProceed: true,
        requiresAcknowledgement: true,
        messageEn: 'This URL shows suspicious characteristics. Proceed with caution.',
        messageTa: 'இந்த URL சந்தேகாஸ்பதமான பண்புகளை காட்டுகிறது. எச்சரிக்கையுடன் தொடரவும்.',
      };
    case RISK_LEVELS.LOW:
      return {
        action: 'proceed_with_caution',
        canProceed: true,
        requiresAcknowledgement: false,
        messageEn: 'No significant threats detected. You may proceed, but remain cautious.',
        messageTa: 'குறிப்பிடத்தக்க அச்சுறுத்தல்கள் கண்டறியப்படவில்லை. நீங்கள் தொடரலாம், ஆனால் எச்சரிக்கையாக இருங்கள்.',
      };
    default:
      return {
        action: 'warn',
        canProceed: true,
        requiresAcknowledgement: true,
        messageEn: 'Insufficient information to assess this URL. Proceed only if you trust the source.',
        messageTa: 'இந்த URL ஐ மதிப்பிட போதுமான தகவல்கள் இல்லை. மூலத்தை நம்பினால் மட்டுமே தொடரவும்.',
      };
  }
}

module.exports = { calculateRisk, getRecommendedAction, RISK_LEVELS };
