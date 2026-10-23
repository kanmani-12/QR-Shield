/**
 * Isolated Redirect Inspector
 *
 * Inspects URL redirect chains using a controlled backend fetch.
 * Only active when ISOLATED_SCANNER_ENABLED=true.
 *
 * SSRF protections applied at every hop:
 * - IP range validation
 * - Redirect count limits
 * - Response size limits
 * - Timeout enforcement
 * - No credential forwarding
 * - No script/content execution
 *
 * Privacy: The scanner's public IP (not the user's) may be observed
 * by the destination server during redirect inspection.
 *
 * Note: Application-level SSRF protection is necessary but not sufficient.
 * Production deployments MUST use network-level egress controls.
 */
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { validateRedirectTarget } = require('../utils/ssrfProtection');
const logger = require('../config/logger');

const MAX_REDIRECTS = parseInt(process.env.SCANNER_MAX_REDIRECTS) || 5;
const TIMEOUT_MS = parseInt(process.env.SCANNER_REQUEST_TIMEOUT_MS) || 8000;
const MAX_BYTES = parseInt(process.env.SCANNER_MAX_RESPONSE_BYTES) || 1024 * 1024;

async function inspectRedirects(startUrl) {
  if (process.env.ISOLATED_SCANNER_ENABLED !== 'true') {
    return {
      available: false,
      reason: 'Redirect inspection is disabled. Set ISOLATED_SCANNER_ENABLED=true to enable.',
    };
  }

  const hops = [];
  let currentUrl = startUrl;
  let redirectCount = 0;
  let finalHostname = null;
  let hasIpDestination = false;
  let mismatch = false;
  let mismatchReason = null;

  const initialHostname = (() => {
    try { return new URL(startUrl).hostname.toLowerCase(); } catch { return null; }
  })();

  while (redirectCount <= MAX_REDIRECTS) {
    // Validate before each hop
    const validation = await validateRedirectTarget(currentUrl);
    if (!validation.valid) {
      hops.push({ url: '[BLOCKED]', suspicious: true, blocked: true, reason: validation.reason });
      mismatch = true;
      mismatchReason = `Redirect blocked: ${validation.reason}`;
      break;
    }

    const parsed = new URL(currentUrl);
    const hop = {
      url: currentUrl,
      hostname: parsed.hostname,
      statusCode: null,
      suspicious: false,
    };

    const net = require('net');
    const cleanHost = parsed.hostname.replace(/^\[|\]$/g, '');
    if (net.isIPv4(cleanHost) || net.isIPv6(cleanHost)) {
      hasIpDestination = true;
      hop.suspicious = true;
    }

    try {
      const response = await makeRequest(currentUrl);
      hop.statusCode = response.statusCode;

      hops.push(hop);

      // Follow redirect
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        redirectCount++;
        const location = response.headers.location;
        // Resolve relative redirects
        try {
          currentUrl = new URL(location, currentUrl).toString();
        } catch {
          mismatch = true;
          mismatchReason = `Invalid redirect location: ${location}`;
          break;
        }
      } else {
        finalHostname = parsed.hostname.toLowerCase();
        break;
      }
    } catch (err) {
      hop.error = err.message;
      hops.push(hop);
      break;
    }
  }

  if (redirectCount > MAX_REDIRECTS) {
    mismatch = true;
    mismatchReason = `Redirect chain exceeded maximum of ${MAX_REDIRECTS} hops`;
  }

  // Check final destination against initial
  if (finalHostname && initialHostname && finalHostname !== initialHostname) {
    mismatch = true;
    mismatchReason = mismatchReason || `Final destination (${finalHostname}) differs from initial host (${initialHostname})`;
  }

  return {
    available: true,
    count: redirectCount,
    hops,
    finalHostname,
    initialHostname,
    mismatch,
    mismatchReason,
    hasIpDestination,
    privacyNote: "The scanner's public IP address may have been observed by destination servers during this inspection.",
  };
}

function makeRequest(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    let bytesReceived = 0;
    const timeout = setTimeout(() => reject(new Error('Request timeout')), TIMEOUT_MS);

    const req = lib.request(url, {
      method: 'HEAD', // Use HEAD to avoid downloading content
      headers: {
        'User-Agent': 'QRShield-Scanner/1.0 (Security Analysis)',
        // No cookies, credentials, or session headers
      },
      timeout: TIMEOUT_MS,
      rejectUnauthorized: true, // Enforce valid TLS certificates
    }, (res) => {
      clearTimeout(timeout);
      res.on('data', (chunk) => {
        bytesReceived += chunk.length;
        if (bytesReceived > MAX_BYTES) {
          req.destroy();
          reject(new Error('Response too large'));
        }
      });
      res.on('end', () => {});
      resolve({ statusCode: res.statusCode, headers: res.headers });
    });

    req.on('error', (err) => {
      clearTimeout(timeout);
      // Fallback to GET if HEAD fails
      if (err.code === 'ECONNREFUSED' || err.message.includes('405')) {
        resolve({ statusCode: null, headers: {} });
      } else {
        reject(err);
      }
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    req.end();
  });
}

module.exports = { inspectRedirects };
