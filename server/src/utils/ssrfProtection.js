/**
 * SSRF Protection Utility
 *
 * Validates URLs and resolved IP addresses to prevent Server-Side Request Forgery.
 * Blocks loopback, private, link-local, multicast, reserved ranges and cloud
 * metadata endpoints.
 *
 * NOTE: Application-level checks are a first layer only.
 * Production deployments MUST also use network-level egress controls
 * (e.g., a firewall that blocks outbound connections to internal ranges).
 */
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');
const logger = require('../config/logger');

// Blocked URL schemes — only http/https allowed for web analysis
const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

// Known cloud metadata endpoint hostnames
const BLOCKED_HOSTNAMES = new Set([
  '169.254.169.254',       // AWS/GCP/Azure IMDS
  'metadata.google.internal',
  'metadata.internal',
]);

// Blocked hostname patterns (regex)
const BLOCKED_HOSTNAME_PATTERNS = [
  /\.internal$/i,
  /\.local$/i,
  /\.localhost$/i,
];

/**
 * IPv4 private/reserved ranges as [network, mask] pairs.
 * All ranges that should never be accessed from the scanner.
 */
const BLOCKED_IPV4_RANGES = [
  { network: '0.0.0.0', prefixLen: 8 },       // Current network
  { network: '10.0.0.0', prefixLen: 8 },       // Private
  { network: '100.64.0.0', prefixLen: 10 },    // Shared address space
  { network: '127.0.0.0', prefixLen: 8 },      // Loopback
  { network: '169.254.0.0', prefixLen: 16 },   // Link-local (APIPA / metadata)
  { network: '172.16.0.0', prefixLen: 12 },    // Private
  { network: '192.0.0.0', prefixLen: 24 },     // IETF Protocol Assignments
  { network: '192.0.2.0', prefixLen: 24 },     // TEST-NET-1
  { network: '192.168.0.0', prefixLen: 16 },   // Private
  { network: '198.18.0.0', prefixLen: 15 },    // Benchmarking
  { network: '198.51.100.0', prefixLen: 24 },  // TEST-NET-2
  { network: '203.0.113.0', prefixLen: 24 },   // TEST-NET-3
  { network: '224.0.0.0', prefixLen: 4 },      // Multicast
  { network: '240.0.0.0', prefixLen: 4 },      // Reserved
  { network: '255.255.255.255', prefixLen: 32 },
];

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isBlockedIPv4(ip) {
  const ipInt = ipv4ToInt(ip);
  for (const range of BLOCKED_IPV4_RANGES) {
    const netInt = ipv4ToInt(range.network);
    const mask = range.prefixLen === 0 ? 0 : (~0 << (32 - range.prefixLen)) >>> 0;
    if ((ipInt & mask) === (netInt & mask)) return true;
  }
  return false;
}

function isBlockedIPv6(ip) {
  // Normalise IPv6 address
  const normalised = ip.toLowerCase().replace(/^::ffff:/, ''); // Strip IPv4-mapped prefix

  // Check if it's an IPv4-mapped address
  if (net.isIPv4(normalised)) {
    return isBlockedIPv4(normalised);
  }

  // Blocked IPv6 ranges
  const blocked = [
    '::1',           // Loopback
    '::',            // Unspecified
    'fe80',          // Link-local (fe80::/10)
    'fc',            // Unique local (fc00::/7)
    'fd',            // Unique local
    'ff',            // Multicast (ff00::/8)
    '100:',          // Discard prefix (100::/64)
  ];

  for (const prefix of blocked) {
    if (normalised.startsWith(prefix)) return true;
  }

  // ::ffff:0:0/96 (IPv4-mapped) — already handled above
  return false;
}

function isBlockedIP(ip) {
  if (net.isIPv4(ip)) return isBlockedIPv4(ip);
  if (net.isIPv6(ip)) return isBlockedIPv6(ip);
  return true; // Unknown format — block by default
}

/**
 * Validate a URL's scheme, hostname, and optionally resolve and validate its IP.
 * Returns { valid: boolean, reason?: string, resolvedIPs?: string[] }
 */
async function validateUrlForScanning(rawUrl, { resolveHostname = true } = {}) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: 'Invalid URL format' };
  }

  // Scheme check
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return {
      valid: false,
      reason: `Unsupported scheme: ${parsed.protocol}. Only HTTP and HTTPS are permitted.`,
    };
  }

  // Suspicious user-info
  if (parsed.username || parsed.password) {
    return { valid: false, reason: 'URLs with embedded credentials are not permitted' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Direct IP literal
  if (net.isIPv4(hostname) || net.isIPv6(hostname.replace(/^\[|\]$/g, ''))) {
    const cleanIp = hostname.replace(/^\[|\]$/g, '');
    if (isBlockedIP(cleanIp)) {
      return { valid: false, reason: `IP address ${cleanIp} is in a blocked range` };
    }
    return { valid: true, resolvedIPs: [cleanIp] };
  }

  // Known blocked hostnames
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return { valid: false, reason: `Hostname ${hostname} is blocked` };
  }

  // Pattern-based hostname blocking
  for (const pattern of BLOCKED_HOSTNAME_PATTERNS) {
    if (pattern.test(hostname)) {
      return { valid: false, reason: `Hostname pattern ${hostname} is blocked` };
    }
  }

  // Hostname resolution and IP validation
  if (resolveHostname) {
    try {
      const records = await dns.lookup(hostname, { all: true, family: 0 });
      const ips = records.map(r => r.address);

      if (ips.length === 0) {
        return { valid: false, reason: 'Hostname does not resolve to any IP address' };
      }

      for (const ip of ips) {
        if (isBlockedIP(ip)) {
          return {
            valid: false,
            reason: `Hostname ${hostname} resolves to blocked IP address ${ip}`,
          };
        }
      }

      return { valid: true, resolvedIPs: ips };
    } catch (err) {
      logger.debug(`DNS resolution failed for ${hostname}: ${err.message}`);
      return { valid: false, reason: `Hostname ${hostname} could not be resolved` };
    }
  }

  return { valid: true };
}

/**
 * Validate a redirect target URL during redirect chain inspection.
 * Same checks apply to each hop.
 */
async function validateRedirectTarget(url) {
  return validateUrlForScanning(url, { resolveHostname: true });
}

module.exports = {
  validateUrlForScanning,
  validateRedirectTarget,
  isBlockedIP,
  isBlockedIPv4,
  isBlockedIPv6,
  ALLOWED_SCHEMES,
  BLOCKED_HOSTNAMES,
};
