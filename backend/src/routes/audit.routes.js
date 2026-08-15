'use strict';

const express = require('express');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

router.get(
  '/me',
  asyncHandler(async (req, res) => {
    const rows = db.prepare(
      'SELECT * FROM audit_logs WHERE actor_user_id = ? ORDER BY created_at DESC LIMIT 200'
    ).all(req.user.id);
    res.json({
      logs: rows.map((r) => ({
        id: r.id,
        action: r.action,
        targetType: r.target_type,
        targetId: r.target_id,
        ip: r.ip_address,
        createdAt: r.created_at,
      })),
    });
  })
);

module.exports = router;
