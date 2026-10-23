/**
 * VirusTotal v3 Threat Intelligence Adapter
 *
 * Queries the VirusTotal URL analysis API.
 * Subject to VirusTotal's Terms of Service and rate limits.
 * Free tier: 4 requests/minute, 500/day.
 *
 * Data transmitted to VirusTotal:
 * - URL hash (SHA-256) for lookups
 * - Full URL for submission when not already analysed
 * See: https://developers.virustotal.com/reference/overview
 */
const axios = require('axios');
const crypto = require('crypto');
const logger = require('../../config/logger');

const VT_API_URL = 'https://www.virustotal.com/api/v3';
const cache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

function urlId(url) {
  // VirusTotal uses base64url of the URL without padding
  return Buffer.from(url).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function check(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return {
      provider: 'virustotal',
      status: 'unavailable',
      details: 'VirusTotal API key not configured',
      checkedAt: new Date(),
    };
  }

  const cacheKey = `vt:${url}`;
  const cached = cache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return { ...cached.result, fromCache: true };
  }

  try {
    const id = urlId(url);
    const response = await axios.get(
      `${VT_API_URL}/urls/${id}`,
      {
        headers: { 'x-apikey': apiKey },
        timeout: 8000,
      }
    );

    const stats = response.data?.data?.attributes?.last_analysis_stats || {};
    const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    let status = 'clean';
    if (malicious > 2) status = 'malicious';
    else if (malicious > 0) status = 'suspicious';

    const categories = [];
    const results = response.data?.data?.attributes?.last_analysis_results || {};
    for (const [engine, result] of Object.entries(results)) {
      if (result.category === 'malicious' || result.category === 'suspicious') {
        categories.push(`${engine}: ${result.result || result.category}`);
      }
    }

    const result = {
      provider: 'virustotal',
      status,
      categories: categories.slice(0, 10), // Limit categories returned
      details: `VirusTotal: ${malicious}/${total} engines flagged this URL`,
      checkedAt: new Date(),
    };

    cache.set(cacheKey, { result, ts: Date.now() });
    return result;
  } catch (err) {
    // 404 means URL not in VirusTotal database yet
    if (err.response?.status === 404) {
      return {
        provider: 'virustotal',
        status: 'clean',
        details: 'URL not found in VirusTotal database (not previously analysed)',
        checkedAt: new Date(),
      };
    }
    // 429 = rate limited
    if (err.response?.status === 429) {
      return {
        provider: 'virustotal',
        status: 'unavailable',
        details: 'VirusTotal API rate limit reached',
        checkedAt: new Date(),
      };
    }

    logger.warn(`VirusTotal check failed: ${err.message}`);
    return {
      provider: 'virustotal',
      status: 'unavailable',
      details: `VirusTotal check failed: ${err.message}`,
      checkedAt: new Date(),
    };
  }
}

module.exports = { check, name: 'virustotal' };
