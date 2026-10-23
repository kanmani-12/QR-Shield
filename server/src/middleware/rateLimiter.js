const rateLimit = require('express-rate-limit');

const createLimiter = (options) => rateLimit({
  windowMs: options.windowMs || parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: options.max || 100,
  message: {
    success: false,
    error: options.message || 'Too many requests. Please try again later.',
    code: 'RATE_LIMITED',
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'test',
});

const globalRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 500,
  message: 'Too many requests from this IP',
});

const authRateLimiter = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many authentication attempts. Please try again in 15 minutes.',
});

const scanRateLimiter = createLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: parseInt(process.env.SCAN_RATE_LIMIT_MAX) || 50,
  message: 'Scan limit reached. Please try again later.',
});

const apiKeyRateLimiter = createLimiter({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: 'API key rate limit exceeded.',
  keyGenerator: (req) => req.headers['x-api-key'] || req.ip,
});

module.exports = { globalRateLimiter, authRateLimiter, scanRateLimiter, apiKeyRateLimiter };
