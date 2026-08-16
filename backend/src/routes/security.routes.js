'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const { body } = require('express-validator');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const { logAudit } = require('../utils/audit');
const { encryptField, decryptField } = require('../utils/crypto');
const { ownerContext } = require('../utils/encryptionContext');
const { generateSecret, provisioningUri, verifyTotp } = require('../utils/totp');
const { BadRequestError, UnauthorizedError } = require('../utils/errors');

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

// ---------------------------------------------------------------------
// V2.0-C MFA endpoints (docs/V2_0_C_PLAN.md §3, audit finding L3): the
// mfa_enabled / mfa_secret_encrypted columns have existed since V1 with no
// code path using them.
// ---------------------------------------------------------------------

router.post(
  '/mfa/setup',
  asyncHandler(async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (user.mfa_enabled) throw new BadRequestError('MFA is already enabled. Disable it first to reconfigure.');

    // Not yet enabled — the secret is stored but mfa_enabled stays 0 until
    // verify-setup proves the user actually configured their authenticator
    // app correctly. Calling /setup again before verifying simply
    // overwrites the pending secret, which is fine — nothing was "live" yet.
    const secret = generateSecret();
    db.prepare('UPDATE users SET mfa_secret_encrypted = ? WHERE id = ?')
      .run(encryptField(secret, ownerContext('users', 'mfa_secret_encrypted', req.user.id)), req.user.id);

    logAudit({ actorUserId: req.user.id, action: 'security.mfa_setup_started', ip: req.ip });
    res.json({
      secret,
      provisioningUri: provisioningUri(secret, user.email),
    });
  })
);

router.post(
  '/mfa/verify-setup',
  [body('code').isString().notEmpty()],
  handleValidation,
  asyncHandler(async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user.mfa_secret_encrypted) throw new BadRequestError('No MFA setup in progress. Call /mfa/setup first.');
    if (user.mfa_enabled) throw new BadRequestError('MFA is already enabled.');

    const secret = decryptField(user.mfa_secret_encrypted, ownerContext('users', 'mfa_secret_encrypted', req.user.id));
    if (!verifyTotp(secret, req.body.code)) {
      logAudit({ actorUserId: req.user.id, action: 'security.mfa_setup_verify_failed', ip: req.ip });
      throw new UnauthorizedError('Invalid verification code');
    }

    db.prepare('UPDATE users SET mfa_enabled = 1 WHERE id = ?').run(req.user.id);
    logAudit({ actorUserId: req.user.id, action: 'security.mfa_enabled', ip: req.ip });
    res.json({ message: 'Multi-factor authentication is now enabled on your account.' });
  })
);

router.post(
  '/mfa/disable',
  [body('password').notEmpty()],
  handleValidation,
  asyncHandler(async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    const matches = await bcrypt.compare(req.body.password, user.password_hash);
    if (!matches) throw new UnauthorizedError('Password is incorrect');

    db.prepare('UPDATE users SET mfa_enabled = 0, mfa_secret_encrypted = NULL WHERE id = ?').run(req.user.id);
    logAudit({ actorUserId: req.user.id, action: 'security.mfa_disabled', ip: req.ip });
    res.json({ message: 'Multi-factor authentication has been disabled.' });
  })
);

router.get(
  '/mfa/status',
  asyncHandler(async (req, res) => {
    const user = db.prepare('SELECT mfa_enabled FROM users WHERE id = ?').get(req.user.id);
    res.json({ enabled: !!user.mfa_enabled });
  })
);

module.exports = router;
