const express = require('express');
const Alert = require('../models/Alert');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// GET /api/notifications — same as alerts but lightweight for nav badge
router.get('/', authenticate, async (req, res, next) => {
  try {
    const filter = req.user.organisation
      ? { $or: [{ user: req.user._id }, { organisation: req.user.organisation }] }
      : { user: req.user._id };

    const [notifications, unreadCount] = await Promise.all([
      Alert.find(filter)
        .sort({ createdAt: -1 })
        .limit(20)
        .select('alertType severity title message isRead createdAt'),
      Alert.countDocuments({ ...filter, isRead: false }),
    ]);

    res.json({ success: true, data: notifications, unreadCount });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
