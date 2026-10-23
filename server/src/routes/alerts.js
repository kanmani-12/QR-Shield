const express = require('express');
const router = express.Router();
const Alert = require('../models/Alert');
const { authenticate } = require('../middleware/auth');
const { validate, paginationSchema } = require('../validators');

// GET /api/alerts
router.get('/', authenticate, validate(paginationSchema, 'query'), async (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const filter = req.user.organisation
      ? { $or: [{ user: req.user._id }, { organisation: req.user.organisation }] }
      : { user: req.user._id };

    const [alerts, total, unreadCount] = await Promise.all([
      Alert.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('scan', 'submittedUrl riskLevel destinationHostname createdAt'),
      Alert.countDocuments(filter),
      Alert.countDocuments({ ...filter, isRead: false }),
    ]);

    res.json({
      success: true,
      data: alerts,
      unreadCount,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/alerts/:id/read
router.patch('/:id/read', authenticate, async (req, res, next) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) return res.status(404).json({ success: false, error: 'Alert not found' });

    const isOwner = (alert.user && alert.user.toString() === req.user._id.toString()) ||
      (alert.organisation && alert.organisation.toString() === req.user.organisation?.toString());
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }

    alert.isRead = true;
    alert.readAt = new Date();
    await alert.save();
    res.json({ success: true, data: alert });
  } catch (err) {
    next(err);
  }
});

// POST /api/alerts/mark-all-read
router.post('/mark-all-read', authenticate, async (req, res, next) => {
  try {
    const filter = req.user.organisation
      ? { $or: [{ user: req.user._id }, { organisation: req.user.organisation }], isRead: false }
      : { user: req.user._id, isRead: false };

    await Alert.updateMany(filter, { isRead: true, readAt: new Date() });
    res.json({ success: true, message: 'All alerts marked as read' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
