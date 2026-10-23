/**
 * Google Safe Browsing v4 Threat Intelligence Adapter
 *
 * Queries the Google Safe Browsing Lookup API.
 * If the API key is not configured, returns unavailable status.
 * Never fabricates results.
 *
 * Data transmitted to Google Safe Browsing:
 * - The URL being checked
 * - Client metadata (application name and version)
 * See: https://developers.google.com/safe-browsing/v4/lookup-api
 */
const axios = require('axios');
const logger = require('../../config/logger');

const GSB_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
];
const PLATFORM_TYPES = ['ANY_PLATFORM'];
const THREAT_ENTRY_TYPES = ['URL'];

// Simple in-memory cache — production should use Redis or MongoDB
const cache = new Map();
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

function getCacheKey(url) {
  return `gsb:${url}`;
}

async function check(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    return {
      provider: 'google_safe_browsing',
      status: 'unavailable',
      details: 'Google Safe Browsing API key not configured',
      checkedAt: new Date(),
    };
  }

  // Check cache
  const cacheKey = getCacheKey(url);
  const cached = cache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return { ...cached.result, fromCache: true };
  }

  try {
    const body = {
      client: { clientId: 'qrshield', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: PLATFORM_TYPES,
        threatEntryTypes: THREAT_ENTRY_TYPES,
        threatEntries: [{ url }],
      },
    };

    const response = await axios.post(
      `${GSB_API_URL}?key=${apiKey}`,
      body,
      { timeout: 5000 }
    );

    const matches = response.data.matches || [];
    const isMalicious = matches.length > 0;

    const result = {
      provider: 'google_safe_browsing',
      status: isMalicious ? 'malicious' : 'clean',
      categories: matches.map(m => m.threatType),
      details: isMalicious
        ? `Google Safe Browsing detected ${matches.length} threat(s): ${matches.map(m => m.threatType).join(', ')}`
        : 'No threats detected by Google Safe Browsing',
      checkedAt: new Date(),
    };

    cache.set(cacheKey, { result, ts: Date.now() });
    return result;
  } catch (err) {
    logger.warn(`Google Safe Browsing check failed: ${err.message}`);
    return {
      provider: 'google_safe_browsing',
      status: 'unavailable',
      details: `Google Safe Browsing check failed: ${err.message}`,
      checkedAt: new Date(),
    };
  }
}

module.exports = { check, name: 'google_safe_browsing' };
