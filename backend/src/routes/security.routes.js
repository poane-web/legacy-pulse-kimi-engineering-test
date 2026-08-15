'use strict';

const express = require('express');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { logAudit } = require('../utils/audit');

const router = express.Router();
router.use(requireAuth);

router.get(
  '/sessions',
  asyncHandler(async (req, res) => {
    const rows = db.prepare(
      "SELECT id, created_at, expires_at FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') ORDER BY created_at DESC"
    ).all(req.user.id);
    res.json({
      sessions: rows.map((r) => ({ id: r.id, createdAt: r.created_at, expiresAt: r.expires_at })),
    });
  })
);

router.post(
  '/sessions/revoke-all',
  asyncHandler(async (req, res) => {
    const info = db.prepare(
      "UPDATE refresh_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ? AND revoked_at IS NULL"
    ).run(req.user.id);
    // V2.0-B (H1): bump token_version too, so this endpoint's promise of
    // "signed out everywhere, including this device" is actually true for
    // the current access token as well, not just future refreshes.
    db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(req.user.id);
    logAudit({ actorUserId: req.user.id, action: 'security.sessions_revoked_all', ip: req.ip, metadata: { count: info.changes } });
    res.json({ message: `Signed out of ${info.changes} session(s). You will need to log in again on other devices.` });
  })
);

module.exports = router;
