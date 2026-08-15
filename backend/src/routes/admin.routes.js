// Admin routes. IMPORTANT (see docs/THREAT_MODEL.md T9): these routes must
// never call decryptField/decryptBuffer. Admins get operational metadata
// (counts, statuses, timestamps) about the platform, never a user's
// decrypted memories, documents, or legacy messages. This file is the one
// place in the codebase that is allowed to read across all users' rows —
// keeping that surface small and reviewable is intentional.
'use strict';

const express = require('express');
const { body, param } = require('express-validator');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { handleValidation } = require('../middleware/validate');
const { logAudit } = require('../utils/audit');
const { NotFoundError, BadRequestError } = require('../utils/errors');

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

router.get(
  '/stats',
  asyncHandler(async (req, res) => {
    const counts = {
      users: db.prepare("SELECT COUNT(*) c FROM users WHERE role = 'owner'").get().c,
      admins: db.prepare("SELECT COUNT(*) c FROM users WHERE role = 'admin'").get().c,
      beneficiaries: db.prepare('SELECT COUNT(*) c FROM beneficiaries').get().c,
      memories: db.prepare('SELECT COUNT(*) c FROM memories').get().c,
      documents: db.prepare('SELECT COUNT(*) c FROM documents').get().c,
      photos: db.prepare('SELECT COUNT(*) c FROM photos').get().c,
      legacyMessagesPending: db.prepare("SELECT COUNT(*) c FROM legacy_messages WHERE status = 'pending'").get().c,
      legacyMessagesReleased: db.prepare("SELECT COUNT(*) c FROM legacy_messages WHERE status = 'released'").get().c,
      storageBytesUsed: (db.prepare('SELECT COALESCE(SUM(size_bytes),0) s FROM documents').get().s)
        + (db.prepare('SELECT COALESCE(SUM(size_bytes),0) s FROM photos').get().s),
    };
    res.json({ stats: counts });
  })
);

router.get(
  '/users',
  asyncHandler(async (req, res) => {
    const rows = db.prepare('SELECT id, email, full_name, role, status, created_at FROM users ORDER BY created_at DESC').all();
    res.json({
      users: rows.map((u) => ({
        id: u.id, email: u.email, fullName: u.full_name, role: u.role, status: u.status, createdAt: u.created_at,
      })),
    });
  })
);

router.put(
  '/users/:id/status',
  [param('id').isInt(), body('status').isIn(['active', 'disabled'])],
  handleValidation,
  asyncHandler(async (req, res) => {
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!target) throw new NotFoundError('User not found');
    if (target.role === 'admin') throw new BadRequestError('Cannot change status of an admin account via this endpoint');

    db.prepare("UPDATE users SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?")
      .run(req.body.status, req.params.id);

    if (req.body.status === 'disabled') {
      db.prepare("UPDATE refresh_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ? AND revoked_at IS NULL")
        .run(req.params.id);
      // V2.0-B (H1): also bump token_version — requireAuth checks this on
      // every request, so a disabled user's already-issued access tokens
      // stop working immediately instead of remaining valid until their
      // natural ≤15min expiry (which was previously the case: only refresh
      // tokens were revoked here).
      db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(req.params.id);
    }

    logAudit({ actorUserId: req.user.id, action: 'admin.user_status_changed', targetType: 'user', targetId: Number(req.params.id), ip: req.ip, metadata: { status: req.body.status } });
    res.json({ message: 'User status updated' });
  })
);

router.get(
  '/audit-logs',
  asyncHandler(async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize || '25', 10)));
    const offset = (page - 1) * pageSize;

    const rows = db.prepare(
      `SELECT al.*, u.email AS actor_email FROM audit_logs al
       LEFT JOIN users u ON u.id = al.actor_user_id
       ORDER BY al.created_at DESC LIMIT ? OFFSET ?`
    ).all(pageSize, offset);
    const total = db.prepare('SELECT COUNT(*) c FROM audit_logs').get().c;

    res.json({
      logs: rows.map((r) => ({
        id: r.id,
        actorEmail: r.actor_email,
        action: r.action,
        targetType: r.target_type,
        targetId: r.target_id,
        ip: r.ip_address,
        metadata: r.metadata_json ? JSON.parse(r.metadata_json) : null,
        createdAt: r.created_at,
      })),
      pagination: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) },
    });
  })
);

module.exports = router;
