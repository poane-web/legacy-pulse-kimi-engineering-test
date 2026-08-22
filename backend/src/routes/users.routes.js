'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const { body } = require('express-validator');

const db = require('../db');
const config = require('../config/env');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const { logAudit } = require('../utils/audit');
const storage = require('../services/storage');
const { BadRequestError, UnauthorizedError, NotFoundError } = require('../utils/errors');

const router = express.Router();
router.use(requireAuth);

router.get(
  '/profile',
  asyncHandler(async (req, res) => {
    const user = db.prepare('SELECT id, email, full_name, role, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) throw new NotFoundError('User not found');
    const profile = db.prepare('SELECT date_of_birth, phone, bio FROM profiles WHERE user_id = ?').get(req.user.id) || {};
    res.json({
      profile: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        createdAt: user.created_at,
        dateOfBirth: profile.date_of_birth || null,
        phone: profile.phone || null,
        bio: profile.bio || null,
      },
    });
  })
);

router.put(
  '/profile',
  [
    body('fullName').optional().trim().isLength({ min: 1, max: 200 }),
    body('dateOfBirth').optional({ nullable: true }).isISO8601().withMessage('must be a valid date'),
    body('phone').optional({ nullable: true }).isString().isLength({ max: 40 }),
    body('bio').optional({ nullable: true }).isString().isLength({ max: 2000 }),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { fullName, dateOfBirth, phone, bio } = req.body;
    if (fullName !== undefined) {
      db.prepare('UPDATE users SET full_name = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\') WHERE id = ?').run(fullName, req.user.id);
    }
    const existing = db.prepare('SELECT user_id FROM profiles WHERE user_id = ?').get(req.user.id);
    if (!existing) {
      db.prepare('INSERT INTO profiles (user_id) VALUES (?)').run(req.user.id);
    }
    db.prepare(
      `UPDATE profiles SET
        date_of_birth = COALESCE(?, date_of_birth),
        phone = COALESCE(?, phone),
        bio = COALESCE(?, bio)
       WHERE user_id = ?`
    ).run(dateOfBirth ?? null, phone ?? null, bio ?? null, req.user.id);

    logAudit({ actorUserId: req.user.id, action: 'profile.updated', ip: req.ip });
    res.json({ message: 'Profile updated' });
  })
);

router.put(
  '/password',
  [
    body('currentPassword').notEmpty(),
    body('newPassword')
      .isLength({ min: 10 })
      .withMessage('must be at least 10 characters')
      .matches(/[0-9]/)
      .withMessage('must contain a number')
      .matches(/[A-Za-z]/)
      .withMessage('must contain a letter'),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user) throw new NotFoundError('User not found');
    const matches = await bcrypt.compare(currentPassword, user.password_hash);
    if (!matches) throw new UnauthorizedError('Current password is incorrect');

    const newHash = await bcrypt.hash(newPassword, config.bcryptCost);
    db.prepare('UPDATE users SET password_hash = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\') WHERE id = ?').run(newHash, req.user.id);

    // Changing password revokes all existing sessions — a reasonable
    // security default (e.g. in case the password change is a response to
    // a suspected compromise).
    db.prepare('UPDATE refresh_tokens SET revoked_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\') WHERE user_id = ? AND revoked_at IS NULL').run(req.user.id);
    // V2.0-B (H1): also bump token_version so any access token issued
    // before this change — which the refresh-token revocation above does
    // NOT invalidate, since access tokens are otherwise stateless — is
    // rejected on its very next use, not just at its natural ≤15min expiry.
    db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(req.user.id);

    logAudit({ actorUserId: req.user.id, action: 'auth.password_changed', ip: req.ip });
    res.json({ message: 'Password updated. Please log in again on other devices.' });
  })
);

router.delete(
  '/me',
  [body('password').notEmpty().withMessage('Password confirmation is required to delete your account')],
  handleValidation,
  asyncHandler(async (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user) throw new NotFoundError('User not found');
    const matches = await bcrypt.compare(req.body.password, user.password_hash);
    if (!matches) throw new UnauthorizedError('Password is incorrect');

    logAudit({ actorUserId: req.user.id, action: 'account.deleted', ip: req.ip });

    // V3 SECURITY FIX (docs/security/V3-THREAT-MODEL.md, finding V3-M2):
    // V1/V2 relied entirely on ON DELETE CASCADE to remove the DB rows for
    // profile, beneficiaries, memories, documents, photos, life_events,
    // legacy_messages, refresh_tokens, and notifications -- but the
    // CASCADE only ever touched database rows. It never called
    // storage.remove() for the encrypted files those `documents`/`photos`
    // rows pointed at, so every uploaded file's ciphertext bytes were
    // silently orphaned on disk forever after account deletion: no DB row
    // references them, so they're unreachable via the API, but the bytes
    // themselves were never actually deleted. For a feature whose entire
    // purpose is deleting a user's data, this is a real gap (storage
    // hygiene, and a "right to be forgotten" concern -- encrypted bytes
    // are still personal data even if inaccessible through the app).
    // Collect and remove the files BEFORE the cascading DB delete, so a
    // failure here surfaces clearly rather than the files becoming
    // permanently unreferenced first.
    const documentsToRemove = db.prepare('SELECT stored_filename FROM documents WHERE owner_id = ?').all(req.user.id);
    const photosToRemove = db.prepare('SELECT stored_filename FROM photos WHERE owner_id = ?').all(req.user.id);
    for (const doc of documentsToRemove) storage.remove(doc.stored_filename);
    for (const photo of photosToRemove) storage.remove(photo.stored_filename);

    // ON DELETE CASCADE removes profile, beneficiaries, memories, documents,
    // photos, life_events, legacy_messages, refresh_tokens, notifications.
    db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);

    res.status(204).end();
  })
);

module.exports = router;
