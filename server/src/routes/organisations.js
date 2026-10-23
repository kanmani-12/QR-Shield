const express = require('express');
const router = express.Router();
const Organisation = require('../models/Organisation');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { authenticate, requireRole } = require('../middleware/auth');
const { validate, createOrgSchema } = require('../validators');

// POST /api/organisations — Create organisation
router.post('/', authenticate, validate(createOrgSchema), async (req, res, next) => {
  try {
    const { name, verifiedDomain, contactEmail } = req.body;
    const org = new Organisation({
      name,
      verifiedDomain: verifiedDomain || null,
      contactEmail,
      members: [{ user: req.user._id, role: 'owner' }],
    });
    await org.save();

    // Assign user to this organisation
    await User.findByIdAndUpdate(req.user._id, { organisation: org._id, role: 'org_admin' });

    await AuditLog.create({
      actor: { userId: req.user._id, userEmail: req.user.email, role: req.user.role },
      action: 'org.create',
      resourceType: 'organisation',
      resourceId: org._id.toString(),
      outcome: 'success',
    });

    res.status(201).json({ success: true, data: org });
  } catch (err) {
    next(err);
  }
});

// GET /api/organisations/mine — Get user's organisation
router.get('/mine', authenticate, async (req, res, next) => {
  try {
    if (!req.user.organisation) {
      return res.json({ success: true, data: null });
    }
    const org = await Organisation.findById(req.user.organisation)
      .populate('members.user', 'name email role');
    res.json({ success: true, data: org });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/organisations/:id/policies — Update security policies
router.patch('/:id/policies', authenticate, requireRole('org_admin'), async (req, res, next) => {
  try {
    const org = await Organisation.findById(req.params.id);
    if (!org) return res.status(404).json({ success: false, error: 'Organisation not found' });

    const isMember = org.members.some(m =>
      m.user.toString() === req.user._id.toString() && ['owner', 'admin'].includes(m.role)
    );
    if (!isMember && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Access denied' });
    }

    const allowedPolicies = ['blockHighRisk', 'warnMediumRisk', 'allowHighRiskOverride', 'retentionDays', 'maxScansPerDay'];
    for (const key of allowedPolicies) {
      if (req.body[key] !== undefined) org.policies[key] = req.body[key];
    }
    await org.save();
    res.json({ success: true, data: org });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
