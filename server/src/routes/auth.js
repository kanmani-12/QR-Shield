const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { authRateLimiter } = require('../middleware/rateLimiter');
const { authenticate } = require('../middleware/auth');
const { validate, registerSchema, loginSchema } = require('../validators');
const logger = require('../config/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret-change-me';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-change-me';
const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES_IN || '15m';
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

function generateTokens(userId) {
  const accessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
  const refreshToken = jwt.sign({ userId }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });
  return { accessToken, refreshToken };
}

function setRefreshCookie(res, refreshToken) {
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/api/auth',
  });
}

// POST /api/auth/register
router.post('/register', authRateLimiter, validate(registerSchema), async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ success: false, error: 'Email already registered', code: 'EMAIL_EXISTS' });
    }

    const user = new User({
      name,
      email,
      passwordHash: password, // Pre-save hook hashes this
    });
    await user.save();

    const { accessToken, refreshToken } = generateTokens(user._id.toString());

    // Store hashed refresh token
    const refreshHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await User.findByIdAndUpdate(user._id, { refreshTokenHash: refreshHash });

    setRefreshCookie(res, refreshToken);

    await AuditLog.create({
      actor: { userId: user._id, userEmail: email, role: 'user' },
      action: 'user.register',
      resourceType: 'user',
      resourceId: user._id.toString(),
      outcome: 'success',
    });

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      accessToken,
      user: user.toJSON(),
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login
router.post('/login', authRateLimiter, validate(loginSchema), async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+passwordHash');
    if (!user) {
      // Use the same error message for missing user and wrong password
      return res.status(401).json({ success: false, error: 'Invalid email or password', code: 'INVALID_CREDENTIALS' });
    }

    if (user.accountStatus !== 'active') {
      return res.status(403).json({ success: false, error: 'Account is not active', code: 'ACCOUNT_INACTIVE' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await AuditLog.create({
        actor: { userEmail: email },
        action: 'user.login.failed',
        resourceType: 'user',
        resourceId: user._id.toString(),
        outcome: 'failure',
      });
      return res.status(401).json({ success: false, error: 'Invalid email or password', code: 'INVALID_CREDENTIALS' });
    }

    const { accessToken, refreshToken } = generateTokens(user._id.toString());
    const refreshHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    await User.findByIdAndUpdate(user._id, {
      refreshTokenHash: refreshHash,
      lastLoginAt: new Date(),
    });

    setRefreshCookie(res, refreshToken);

    await AuditLog.create({
      actor: { userId: user._id, userEmail: email, role: user.role },
      action: 'user.login',
      resourceType: 'user',
      resourceId: user._id.toString(),
      outcome: 'success',
    });

    res.json({
      success: true,
      message: 'Login successful',
      accessToken,
      user: user.toJSON(),
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/refresh
router.post('/refresh', async (req, res, next) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) {
      return res.status(401).json({ success: false, error: 'Refresh token required', code: 'NO_REFRESH_TOKEN' });
    }

    const decoded = jwt.verify(token, JWT_REFRESH_SECRET);
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findById(decoded.userId).select('+refreshTokenHash');
    if (!user || user.refreshTokenHash !== tokenHash) {
      return res.status(401).json({ success: false, error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
    }

    const { accessToken, refreshToken: newRefresh } = generateTokens(user._id.toString());
    const newHash = crypto.createHash('sha256').update(newRefresh).digest('hex');
    await User.findByIdAndUpdate(user._id, { refreshTokenHash: newHash });

    setRefreshCookie(res, newRefresh);
    res.json({ success: true, accessToken });
  } catch (err) {
    if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, error: 'Refresh token expired or invalid', code: 'REFRESH_EXPIRED' });
    }
    next(err);
  }
});

// POST /api/auth/logout
router.post('/logout', authenticate, async (req, res, next) => {
  try {
    await User.findByIdAndUpdate(req.user._id, { refreshTokenHash: null });
    res.clearCookie('refreshToken', { path: '/api/auth' });
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    next(err);
  }
});

// GET /api/auth/me
router.get('/me', authenticate, (req, res) => {
  res.json({ success: true, user: req.user });
});

module.exports = router;
