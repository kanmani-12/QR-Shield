const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const { authenticate } = require('../middleware/auth');

// GET /api/analytics/trends — Daily scan trends (last 30 days)
router.get('/trends', authenticate, async (req, res, next) => {
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const filter = { createdAt: { $gte: thirtyDaysAgo } };
    if (req.user.role !== 'admin') filter.user = req.user._id;

    const trends = await Scan.aggregate([
      { $match: filter },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          total: { $sum: 1 },
          high: { $sum: { $cond: [{ $eq: ['$riskLevel', 'HIGH'] }, 1, 0] } },
          medium: { $sum: { $cond: [{ $eq: ['$riskLevel', 'MEDIUM'] }, 1, 0] } },
          low: { $sum: { $cond: [{ $eq: ['$riskLevel', 'LOW'] }, 1, 0] } },
          unknown: { $sum: { $cond: [{ $eq: ['$riskLevel', 'UNKNOWN'] }, 1, 0] } },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    res.json({ success: true, data: trends });
  } catch (err) {
    next(err);
  }
});

// GET /api/analytics/risk-distribution
router.get('/risk-distribution', authenticate, async (req, res, next) => {
  try {
    const filter = req.user.role !== 'admin' ? { user: req.user._id } : {};
    const dist = await Scan.aggregate([
      { $match: filter },
      { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
    ]);
    const result = { HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    for (const d of dist) if (d._id) result[d._id] = d.count;
    res.json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
});

// GET /api/analytics/threat-categories
router.get('/threat-categories', authenticate, async (req, res, next) => {
  try {
    const filter = req.user.role !== 'admin' ? { user: req.user._id } : {};
    const cats = await Scan.aggregate([
      { $match: { ...filter, 'providerResults.categories': { $exists: true, $ne: [] } } },
      { $unwind: '$providerResults' },
      { $unwind: '$providerResults.categories' },
      { $group: { _id: '$providerResults.categories', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]);
    res.json({ success: true, data: cats.map(c => ({ category: c._id, count: c.count })) });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
