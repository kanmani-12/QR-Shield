const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');
const { validate, updatePasswordSchema } = require('../validators');

// GET /api/users/profile
router.get('/profile', authenticate, async (req, res) => {
  res.json({ success: true, data: req.user });
});

// PATCH /api/users/profile
router.patch('/profile', authenticate, async (req, res, next) => {
  try {
    const allowed = ['name', 'languagePreference', 'notificationPreferences'];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true, runValidators: true });
    res.json({ success: true, data: user });
  } catch (err) {
    next(err);
  }
});

// POST /api/users/change-password
router.post('/change-password', authenticate, validate(updatePasswordSchema), async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('+passwordHash');
    const isMatch = await user.comparePassword(req.body.currentPassword);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }
    user.passwordHash = req.body.newPassword; // Pre-save hook hashes it
    await user.save();
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
