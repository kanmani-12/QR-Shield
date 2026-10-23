const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const User = require('../models/User');
const Organisation = require('../models/Organisation');
const Alert = require('../models/Alert');
const AuditLog = require('../models/AuditLog');
const TrustedQR = require('../models/TrustedQR');
const { authenticate, requireRole } = require('../middleware/auth');
const { validate, paginationSchema } = require('../validators');

const adminOnly = [authenticate, requireRole('admin')];

// GET /api/admin/stats — Dashboard statistics
router.get('/stats', ...adminOnly, async (req, res, next) => {
  try {
    const now = new Date();
    const startOfDay = new Date(now); startOfDay.setHours(0, 0, 0, 0);
    const startOfWeek = new Date(now); startOfWeek.setDate(now.getDate() - 7);
    const startOfMonth = new Date(now); startOfMonth.setDate(1); startOfMonth.setHours(0, 0, 0, 0);

    const [
      totalScans, scansToday, scansThisWeek, scansThisMonth,
      riskDist, totalUsers, totalOrgs, highRiskAlerts,
      recentScans, topHostnames
    ] = await Promise.all([
      Scan.countDocuments(),
      Scan.countDocuments({ createdAt: { $gte: startOfDay } }),
      Scan.countDocuments({ createdAt: { $gte: startOfWeek } }),
      Scan.countDocuments({ createdAt: { $gte: startOfMonth } }),
      Scan.aggregate([{ $group: { _id: '$riskLevel', count: { $sum: 1 } } }]),
      User.countDocuments(),
      Organisation.countDocuments(),
      Alert.countDocuments({ severity: 'critical', isRead: false }),
      Scan.find().sort({ createdAt: -1 }).limit(10)
        .select('submittedUrl destinationHostname riskLevel scanType createdAt status'),
      Scan.aggregate([
        { $match: { destinationHostname: { $ne: null } } },
        { $group: { _id: '$destinationHostname', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
    ]);

    const riskDistMap = {};
    for (const r of riskDist) riskDistMap[r._id] = r.count;

    res.json({
      success: true,
      data: {
        scans: { total: totalScans, today: scansToday, thisWeek: scansThisWeek, thisMonth: scansThisMonth },
        riskDistribution: {
          HIGH: riskDistMap['HIGH'] || 0,
          MEDIUM: riskDistMap['MEDIUM'] || 0,
          LOW: riskDistMap['LOW'] || 0,
          UNKNOWN: riskDistMap['UNKNOWN'] || 0,
        },
        users: totalUsers,
        organisations: totalOrgs,
        unreadHighRiskAlerts: highRiskAlerts,
        recentScans,
        topHostnames: topHostnames.map(h => ({ hostname: h._id, count: h.count })),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/scans — All scans with filtering and pagination
router.get('/scans', ...adminOnly, validate(paginationSchema, 'query'), async (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const { riskLevel, startDate, endDate, search } = req.query;

    const filter = {};
    if (riskLevel) filter.riskLevel = riskLevel;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    if (search) {
      filter.$or = [
        { submittedUrl: { $regex: search, $options: 'i' } },
        { destinationHostname: { $regex: search, $options: 'i' } },
      ];
    }

    const [scans, total] = await Promise.all([
      Scan.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate('user', 'name email'),
      Scan.countDocuments(filter),
    ]);

    res.json({
      success: true,
      data: scans,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/users — All users
router.get('/users', ...adminOnly, validate(paginationSchema, 'query'), async (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const [users, total] = await Promise.all([
      User.find().sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('organisation', 'name'),
      User.countDocuments(),
    ]);
    res.json({ success: true, data: users, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/admin/users/:id/status
router.patch('/users/:id/status', ...adminOnly, async (req, res, next) => {
  try {
    const { status } = req.body;
    if (!['active', 'suspended'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }
    const user = await User.findByIdAndUpdate(req.params.id, { accountStatus: status }, { new: true });
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    await AuditLog.create({
      actor: { userId: req.user._id, userEmail: req.user.email, role: req.user.role },
      action: `user.status.${status}`,
      resourceType: 'user',
      resourceId: user._id.toString(),
      outcome: 'success',
    });

    res.json({ success: true, data: user });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/audit-logs
router.get('/audit-logs', ...adminOnly, validate(paginationSchema, 'query'), async (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const { action, resourceType, startDate, endDate } = req.query;
    const filter = {};
    if (action) filter.action = { $regex: action, $options: 'i' };
    if (resourceType) filter.resourceType = resourceType;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }

    const [logs, total] = await Promise.all([
      AuditLog.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
      AuditLog.countDocuments(filter),
    ]);
    res.json({ success: true, data: logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/export/scans — CSV export
router.get('/export/scans', ...adminOnly, async (req, res, next) => {
  try {
    const { startDate, endDate, riskLevel } = req.query;
    const filter = {};
    if (riskLevel) filter.riskLevel = riskLevel;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }

    const scans = await Scan.find(filter)
      .sort({ createdAt: -1 })
      .limit(10000)
      .select('destinationHostname riskLevel riskScore scanType status createdAt isDemo');

    const csv = [
      'ID,Hostname,Risk Level,Risk Score,Scan Type,Status,Date,Demo',
      ...scans.map(s =>
        `${s._id},"${s.destinationHostname || ''}",${s.riskLevel},${s.riskScore || ''},${s.scanType},${s.status},${s.createdAt.toISOString()},${s.isDemo}`
      ),
    ].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="qrshield-scans.csv"');
    res.send(csv);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
