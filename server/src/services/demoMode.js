/**
 * Demo Mode Service
 *
 * Activated when no real threat-intelligence API keys are configured,
 * or when FORCE_DEMO_MODE=true.
 *
 * Demo mode uses clearly labelled synthetic responses — it never fabricates
 * real threat-intelligence data or claims to have queried external providers.
 */

function isActive() {
  if (process.env.FORCE_DEMO_MODE === 'true') return true;
  // Active if NO real provider keys are configured
  const hasGsb = Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY);
  const hasVt = Boolean(process.env.VIRUSTOTAL_API_KEY);
  return !hasGsb && !hasVt;
}

/**
 * Return a clearly labelled demo result for URL analysis.
 * The result is deterministic based on URL characteristics so it behaves
 * consistently across requests.
 */
function getDemoResult(url) {
  const lower = (url || '').toLowerCase();

  let riskLevel = 'UNKNOWN';
  let riskScore = 30;
  const evidence = [];

  // Simulate some basic pattern detection (clearly labelled as demo)
  if (lower.includes('malware') || lower.includes('phish') || lower.includes('virus')) {
    riskLevel = 'HIGH';
    riskScore = 90;
    evidence.push({
      factor: 'DEMO: Suspicious keyword in URL',
      severity: 'high',
      description: '[DEMO MODE] URL contains a keyword commonly found in malicious links. This is a simulated result — no real scan was performed.',
    });
  } else if (lower.includes('suspicious') || lower.includes('hack') || lower.includes('free-gift')) {
    riskLevel = 'MEDIUM';
    riskScore = 55;
    evidence.push({
      factor: 'DEMO: Potentially suspicious URL pattern',
      severity: 'medium',
      description: '[DEMO MODE] URL matches a heuristic pattern. This is a simulated result — configure threat-intelligence API keys for real analysis.',
    });
  } else if (lower.startsWith('https://') && !lower.includes('bit.ly') && !lower.includes('tinyurl')) {
    riskLevel = 'LOW';
    riskScore = 15;
    evidence.push({
      factor: 'DEMO: Standard HTTPS URL with no immediate heuristic concerns',
      severity: 'info',
      description: '[DEMO MODE] No heuristic flags detected. Note: LOW risk in demo mode does not mean the URL is verified safe — configure real threat-intelligence providers for accurate results.',
    });
  }

  return {
    isDemo: true,
    riskLevel,
    riskScore,
    evidence,
    providers: [
      {
        provider: 'DEMO_MODE',
        status: 'demo',
        details: 'No real threat-intelligence providers are configured. Results are simulated for demonstration purposes only.',
        checkedAt: new Date(),
      },
    ],
    demoWarning: 'DEMO MODE ACTIVE: Threat-intelligence API keys are not configured. These results are simulated and must not be used for real security decisions.',
  };
}

module.exports = { isActive, getDemoResult };
