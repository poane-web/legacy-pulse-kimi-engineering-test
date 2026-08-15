'use strict';

const express = require('express');
const { body } = require('express-validator');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { requireOwnership } = require('../middleware/rbac');
const { handleValidation } = require('../middleware/validate');
const { logAudit } = require('../utils/audit');
const { sha256Hex, randomToken } = require('../utils/crypto');
const { NotFoundError, ForbiddenError, ConflictError } = require('../utils/errors');
const config = require('../config/env');

const router = express.Router();

function toDTO(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    status: row.status,
    linked: !!row.linked_user_id,
    createdAt: row.created_at,
  };
}

router.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const rows = db.prepare('SELECT * FROM trusted_contacts WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json({ trustedContacts: rows.map(toDTO) });
  })
);

router.post(
  '/',
  requireAuth,
  [body('fullName').trim().isLength({ min: 1, max: 200 }), body('email').isEmail().normalizeEmail()],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { fullName, email } = req.body;
    const rawToken = randomToken(24);
    const tokenHash = sha256Hex(rawToken);
    const info = db.prepare(
      'INSERT INTO trusted_contacts (owner_id, full_name, email, invite_token_hash) VALUES (?, ?, ?, ?)'
    ).run(req.user.id, fullName, email, tokenHash);

    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.created', targetType: 'trusted_contact', targetId: info.lastInsertRowid, ip: req.ip });

    const row = db.prepare('SELECT * FROM trusted_contacts WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({
      trustedContact: toDTO(row),
      inviteLink: `/claim-invite?type=trusted_contact&token=${rawToken}&email=${encodeURIComponent(email)}`,
    });
  })
);

router.delete(
  '/:id',
  requireAuth,
  requireOwnership((req) => db.prepare('SELECT * FROM trusted_contacts WHERE id = ?').get(req.params.id), 'trusted_contact'),
  asyncHandler(async (req, res) => {
    db.prepare('DELETE FROM trusted_contacts WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.revoked', targetType: 'trusted_contact', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

router.post(
  '/claim',
  requireAuth,
  [body('token').isString().isLength({ min: 10 })],
  handleValidation,
  asyncHandler(async (req, res) => {
    const tokenHash = sha256Hex(req.body.token);
    const row = db.prepare('SELECT * FROM trusted_contacts WHERE invite_token_hash = ? AND status = ?').get(tokenHash, 'pending');
    if (!row) throw new NotFoundError('Invite not found or already used');
    db.prepare('UPDATE trusted_contacts SET linked_user_id = ?, status = ?, invite_token_hash = NULL WHERE id = ?')
      .run(req.user.id, 'active', row.id);
    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.invite_claimed', targetType: 'trusted_contact', targetId: row.id, ip: req.ip });
    res.json({ message: 'You are now a trusted contact for this account.' });
  })
);

// Two-person rule: a trusted contact confirms an owner's release-trigger
// event (e.g. "this person has passed away"). Requires
// config.requiredReleaseConfirmations independent confirmations before any
// trusted_contact_confirmation-type legacy message is released. See
// docs/ARCHITECTURE.md §6 and docs/THREAT_MODEL.md T5.
router.post(
  '/confirm/:ownerId',
  requireAuth,
  asyncHandler(async (req, res) => {
    const ownerId = Number(req.params.ownerId);
    const contact = db.prepare('SELECT * FROM trusted_contacts WHERE owner_id = ? AND linked_user_id = ? AND status = ?')
      .get(ownerId, req.user.id, 'active');
    if (!contact) throw new ForbiddenError('You are not an active trusted contact for this account');

    const existing = db.prepare('SELECT 1 FROM release_confirmations WHERE owner_id = ? AND trusted_contact_id = ?').get(ownerId, contact.id);
    if (existing) throw new ConflictError('You have already submitted a confirmation for this account');

    db.prepare('INSERT INTO release_confirmations (owner_id, trusted_contact_id) VALUES (?, ?)').run(ownerId, contact.id);
    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.confirmation_submitted', targetType: 'user', targetId: ownerId, ip: req.ip });

    const count = db.prepare('SELECT COUNT(*) AS c FROM release_confirmations WHERE owner_id = ?').get(ownerId).c;
    const required = config.requiredReleaseConfirmations;

    if (count >= required) {
      // Release all pending trusted_contact_confirmation messages for this owner.
      const pending = db.prepare(
        "SELECT * FROM legacy_messages WHERE owner_id = ? AND release_type = 'trusted_contact_confirmation' AND status = 'pending'"
      ).all(ownerId);
      const release = db.prepare("UPDATE legacy_messages SET status = 'released', released_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?");
      const notify = db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)');
      for (const msg of pending) {
        release.run(msg.id);
        const beneficiary = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(msg.beneficiary_id);
        logAudit({ action: 'legacy_message.released', targetType: 'legacy_message', targetId: msg.id, metadata: { trigger: 'trusted_contact_confirmation' } });
        if (beneficiary && beneficiary.linked_user_id) {
          notify.run(beneficiary.linked_user_id, 'message_released', `A legacy message titled "${msg.title}" has been released to you.`);
        }
      }
    }

    res.json({ message: 'Confirmation recorded', confirmationsReceived: count, confirmationsRequired: required });
  })
);

module.exports = router;
