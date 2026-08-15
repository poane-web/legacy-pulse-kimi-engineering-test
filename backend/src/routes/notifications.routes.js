'use strict';

const express = require('express');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { NotFoundError, ForbiddenError } = require('../utils/errors');

const router = express.Router();
router.use(requireAuth);

router.get(
  '/',
  asyncHandler(async (req, res) => {
    const rows = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.user.id);
    res.json({
      notifications: rows.map((n) => ({
        id: n.id, type: n.type, message: n.message, read: !!n.read_at, createdAt: n.created_at,
      })),
    });
  })
);

router.put(
  '/:id/read',
  asyncHandler(async (req, res) => {
    const row = db.prepare('SELECT * FROM notifications WHERE id = ?').get(req.params.id);
    if (!row) throw new NotFoundError('Notification not found');
    if (row.user_id !== req.user.id) throw new ForbiddenError('Not your notification');
    db.prepare("UPDATE notifications SET read_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?").run(req.params.id);
    res.json({ message: 'Marked read' });
  })
);

module.exports = router;
