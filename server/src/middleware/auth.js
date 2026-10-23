const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../config/logger');

/**
 * Authenticate using JWT Bearer token or HttpOnly cookie.
 */
async function authenticate(req, res, next) {
  try {
    let token = null;

    // Check Authorization header first
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }

    // Fall back to cookie
    if (!token && req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'NO_TOKEN',
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret-change-me');

    const user = await User.findById(decoded.userId).select('-passwordHash -refreshTokenHash');
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    if (user.accountStatus !== 'active') {
      return res.status(403).json({
        success: false,
        error: 'Account is not active',
        code: 'ACCOUNT_INACTIVE',
      });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
        code: 'TOKEN_EXPIRED',
      });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
      });
    }
    logger.error('Auth middleware error:', err);
    next(err);
  }
}

/**
 * Optional authentication — attach user if token present, continue if not.
 */
async function optionalAuth(req, res, next) {
  try {
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) token = authHeader.split(' ')[1];
    if (!token && req.cookies && req.cookies.accessToken) token = req.cookies.accessToken;

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret-change-me');
      const user = await User.findById(decoded.userId).select('-passwordHash -refreshTokenHash');
      if (user && user.accountStatus === 'active') req.user = user;
    }
  } catch (_) {
    // Ignore auth errors in optional mode
  }
  next();
}

/**
 * Require a specific role or higher.
 * Role hierarchy: user < org_admin < admin
 */
function requireRole(...roles) {
  const hierarchy = { user: 0, org_admin: 1, admin: 2 };
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    const userLevel = hierarchy[req.user.role] ?? 0;
    const required = Math.max(...roles.map(r => hierarchy[r] ?? 0));
    if (userLevel < required) {
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
        code: 'FORBIDDEN',
      });
    }
    next();
  };
}

module.exports = { authenticate, optionalAuth, requireRole };
