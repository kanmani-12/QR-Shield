const { URL } = require('url');

// URL shortener hostnames that should be flagged for redirect inspection
const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'youtu.be', 'short.link', 'tiny.cc', 'rb.gy', 'cutt.ly',
  'short.io', 'bl.ink', 'smarturl.it', 'linktr.ee', 'lnkd.in', 'fb.me',
]);

// File-sharing hostnames
const FILE_SHARING_HOSTS = new Set([
  'drive.google.com', 'docs.google.com', 'sheets.google.com', 'slides.google.com',
  'dropbox.com', 'www.dropbox.com',
  'onedrive.live.com', '1drv.ms',
  'sharepoint.com', 'wetransfer.com', 'box.com',
]);

// Suspicious TLDs
const SUSPICIOUS_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.pw', '.top',
  '.click', '.link', '.download', '.zip', '.mov',
]);

// Suspicious user-info patterns that indicate deception
const SUSPICIOUS_PATTERNS = [
  /[@]/,                        // User-info in URL (e.g., user@evil.com@legit.com)
  /%[0-9a-fA-F]{2}/,            // Percent-encoded characters (flag for inspection)
  /\.(exe|bat|cmd|vbs|ps1|scr|pif|msi|jar|apk)(\?|$)/i,  // Executable extensions
];

// Punycode domains (IDN homograph attacks)
const PUNYCODE_PATTERN = /xn--/i;

/**
 * Parse and validate a URL for web analysis.
 * Returns a structured analysis object.
 */
function parseAndValidateUrl(rawUrl) {
  const result = {
    rawUrl,
    isValid: false,
    parsed: null,
    hostname: null,
    scheme: null,
    port: null,
    path: null,
    query: null,
    isShortened: false,
    isFileSharing: false,
    isSuspiciousTld: false,
    hasPunycode: false,
    hasPercentEncoding: false,
    hasUserInfo: false,
    hasExecutableExtension: false,
    isIpLiteral: false,
    hasNonStandardPort: false,
    flags: [],
    errors: [],
  };

  // Trim and basic length check
  const trimmed = (rawUrl || '').trim();
  if (!trimmed) {
    result.errors.push('URL is empty');
    return result;
  }
  if (trimmed.length > 2048) {
    result.errors.push('URL exceeds maximum length of 2048 characters');
    return result;
  }

  // Add scheme if missing (support "example.com/path" style input)
  let urlString = trimmed;
  if (!/^https?:\/\//i.test(urlString) && !/:\/\//.test(urlString)) {
    urlString = 'https://' + urlString;
  }

  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    result.errors.push('URL could not be parsed — check for invalid characters or structure');
    return result;
  }

  result.parsed = parsed;
  result.scheme = parsed.protocol;
  result.hostname = parsed.hostname.toLowerCase();
  result.port = parsed.port || null;
  result.path = parsed.pathname;
  result.query = parsed.search;
  result.isValid = true;

  // Scheme check
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    result.flags.push({
      type: 'unsupported_scheme',
      severity: 'high',
      message: `Scheme "${parsed.protocol}" is not supported for web analysis`,
    });
    result.isValid = false;
  }

  // User-info (credentials in URL)
  if (parsed.username || parsed.password) {
    result.hasUserInfo = true;
    result.flags.push({
      type: 'user_info_in_url',
      severity: 'high',
      message: 'URL contains embedded credentials, which is unusual and potentially deceptive',
    });
  }

  // IP literal hostname
  const net = require('net');
  const cleanHostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIPv4(cleanHostname) || net.isIPv6(cleanHostname)) {
    result.isIpLiteral = true;
    result.flags.push({
      type: 'ip_literal',
      severity: 'medium',
      message: 'URL uses a raw IP address instead of a domain name, which is uncommon for legitimate services',
    });
  }

  // URL shortener
  const fullHostname = parsed.hostname.toLowerCase();
  if (KNOWN_SHORTENERS.has(fullHostname) || KNOWN_SHORTENERS.has(fullHostname.replace(/^www\./, ''))) {
    result.isShortened = true;
    result.flags.push({
      type: 'shortened_url',
      severity: 'medium',
      message: 'This appears to be a shortened URL. The final destination is not visible from the URL alone.',
    });
  }

  // File sharing
  if (FILE_SHARING_HOSTS.has(fullHostname) || FILE_SHARING_HOSTS.has(fullHostname.replace(/^www\./, ''))) {
    result.isFileSharing = true;
  }

  // Suspicious TLD
  for (const tld of SUSPICIOUS_TLDS) {
    if (parsed.hostname.endsWith(tld)) {
      result.isSuspiciousTld = true;
      result.flags.push({
        type: 'suspicious_tld',
        severity: 'low',
        message: `The domain uses the "${tld}" extension, which is associated with a higher rate of abuse`,
      });
      break;
    }
  }

  // Punycode / IDN homograph
  if (PUNYCODE_PATTERN.test(parsed.hostname)) {
    result.hasPunycode = true;
    result.flags.push({
      type: 'punycode_domain',
      severity: 'medium',
      message: 'Domain contains international characters that may be used to impersonate legitimate websites',
    });
  }

  // Percent encoding
  if (/%[0-9a-fA-F]{2}/.test(trimmed)) {
    result.hasPercentEncoding = true;
    result.flags.push({
      type: 'percent_encoding',
      severity: 'low',
      message: 'URL contains encoded characters which may be used to obscure the actual destination',
    });
  }

  // Executable extension
  if (/\.(exe|bat|cmd|vbs|ps1|scr|pif|msi|jar|apk)(\?|#|$)/i.test(parsed.pathname)) {
    result.hasExecutableExtension = true;
    result.flags.push({
      type: 'executable_extension',
      severity: 'high',
      message: 'URL appears to link directly to an executable file, which is a significant risk indicator',
    });
  }

  // Non-standard port
  const standardPorts = { 'http:': '80', 'https:': '443' };
  if (parsed.port && parsed.port !== standardPorts[parsed.protocol]) {
    result.hasNonStandardPort = true;
    result.flags.push({
      type: 'non_standard_port',
      severity: 'low',
      message: `URL uses non-standard port ${parsed.port}, which is unusual for public websites`,
    });
  }

  // Long hostname (subdomain abuse)
  if (parsed.hostname.split('.').length > 5) {
    result.flags.push({
      type: 'excessive_subdomains',
      severity: 'low',
      message: 'URL has an unusually large number of subdomains',
    });
  }

  return result;
}

/**
 * Determine if a hostname appears to be a lookalike for a known brand.
 * Simplified heuristic — not a complete solution.
 */
function detectLookalike(hostname) {
  const brands = [
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal',
    'netflix', 'dropbox', 'onedrive', 'outlook', 'gmail', 'youtube',
    'instagram', 'twitter', 'linkedin', 'github', 'atlassian', 'slack',
    'zoom', 'teams', 'sharepoint',
  ];

  const cleanHost = hostname.toLowerCase().replace(/^www\./, '');
  const domainPart = cleanHost.split('.')[0];

  for (const brand of brands) {
    if (domainPart === brand) continue; // Exact match is fine (heuristic)

    // Levenshtein-like: brand appears in domain but domain doesn't equal brand TLD
    if (domainPart.includes(brand) && !cleanHost.endsWith(`.${brand}.com`) && !cleanHost.startsWith(`${brand}.`)) {
      return {
        detected: true,
        targetBrand: brand,
        message: `Domain may be impersonating "${brand}"`,
      };
    }

    // Homoglyph-style: substitutions (simplified)
    const normalised = domainPart
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w');

    if (normalised === brand) {
      return {
        detected: true,
        targetBrand: brand,
        message: `Domain "${domainPart}" may be a character-substitution lookalike of "${brand}"`,
      };
    }
  }
  return { detected: false };
}

module.exports = { parseAndValidateUrl, detectLookalike, KNOWN_SHORTENERS, FILE_SHARING_HOSTS };
