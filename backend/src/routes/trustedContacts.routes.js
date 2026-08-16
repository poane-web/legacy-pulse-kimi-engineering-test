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
const { NotFoundError, ForbiddenError, ConflictError, BadRequestError } = require('../utils/errors');

const router = express.Router();

function toDTO(row) {
  return { id: row.id, fullName: row.full_name, email: row.email, status: row.status, linked: !!row.linked_user_id, createdAt: row.created_at };
}

router.get('/', requireAuth, asyncHandler(async (req, res) => {
  const rows = db.prepare('SELECT * FROM trusted_contacts WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json({ trustedContacts: rows.map(toDTO) });
}));

router.post('/', requireAuth, [body('fullName').trim().isLength({ min: 1, max: 200 }), body('email').isEmail().normalizeEmail()], handleValidation,
  asyncHandler(async (req, res) => {
    const rawToken = randomToken(24);
    const tokenHash = sha256Hex(rawToken);
    const info = db.prepare('INSERT INTO trusted_contacts (owner_id, full_name, email, invite_token_hash) VALUES (?, ?, ?, ?)').run(req.user.id, req.body.fullName, req.body.email, tokenHash);
    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.created', targetType: 'trusted_contact', targetId: info.lastInsertRowid, ip: req.ip });
    const row = db.prepare('SELECT * FROM trusted_contacts WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ trustedContact: toDTO(row), inviteLink: `/claim-invite?type=trusted_contact&token=${rawToken}&email=${encodeURIComponent(req.body.email)}` });
  }));

router.delete('/:id', requireAuth, requireOwnership((req) => db.prepare('SELECT * FROM trusted_contacts WHERE id = ?').get(req.params.id), 'trusted_contact'),
  asyncHandler(async (req, res) => {
    db.prepare('DELETE FROM trusted_contacts WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.revoked', targetType: 'trusted_contact', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  }));

router.post('/claim', requireAuth, [body('token').isString().isLength({ min: 10 }), body('email').optional().isEmail().normalizeEmail()], handleValidation,
  asyncHandler(async (req, res) => {
    const tokenHash = sha256Hex(req.body.token);
    const row = db.prepare('SELECT * FROM trusted_contacts WHERE invite_token_hash = ? AND status = ?').get(tokenHash, 'pending');
    if (!row) throw new NotFoundError('Invite not found or already used');
    if (row.email.toLowerCase() !== req.user.email.toLowerCase()) {
      throw new BadRequestError('This invite was issued to a different email address');
    }
    db.prepare('UPDATE trusted_contacts SET linked_user_id = ?, status = ?, invite_token_hash = NULL WHERE id = ?')
      .run(req.user.id, 'active', row.id);
    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.invite_claimed', targetType: 'trusted_contact', targetId: row.id, ip: req.ip });
    res.json({ message: 'You are now a trusted contact for this account.' });
  }));

// A confirmation is a release authorization for ONE specific message. It is
// deliberately not an owner-wide flag: otherwise two confirmations for one
// message could retroactively release every other pending message belonging
// to the same owner.
router.post('/confirm/:messageId', requireAuth, asyncHandler(async (req, res) => {
  const messageId = Number(req.params.messageId);
  if (!Number.isSafeInteger(messageId) || messageId <= 0) throw new BadRequestError('Invalid messageId');

  const message = db.prepare(
    "SELECT * FROM legacy_messages WHERE id = ? AND release_type = 'trusted_contact_confirmation'"
  ).get(messageId);
  if (!message) throw new NotFoundError('Confirmation target not found');
  if (message.status !== 'pending') throw new ConflictError('This message is no longer pending release');

  const contact = db.prepare(
    'SELECT * FROM trusted_contacts WHERE owner_id = ? AND linked_user_id = ? AND status = ?'
  ).get(message.owner_id, req.user.id, 'active');
  if (!contact) throw new ForbiddenError('You are not an active trusted contact for this account');

  const confirmationTx = db.transaction(() => {
    try {
      db.prepare(
        'INSERT INTO release_confirmations (owner_id, legacy_message_id, trusted_contact_id) VALUES (?, ?, ?)'
      ).run(message.owner_id, message.id, contact.id);
    } catch (err) {
      if (String(err.message).includes('UNIQUE constraint failed')) {
        throw new ConflictError('You have already submitted a confirmation for this message');
      }
      throw err;
    }

    const count = db.prepare(
      'SELECT COUNT(*) AS c FROM release_confirmations WHERE legacy_message_id = ?'
    ).get(message.id).c;
    const required = message.required_confirmations;
    let released = false;

    if (count >= required) {
      const result = db.prepare(
        "UPDATE legacy_messages SET status = 'released', released_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ? AND status = 'pending' AND release_type = 'trusted_contact_confirmation'"
      ).run(message.id);
      released = result.changes === 1;
    }

    return { count, required, released };
  });

  const result = confirmationTx();
  logAudit({
    actorUserId: req.user.id,
    action: 'trusted_contact.confirmation_submitted',
    targetType: 'legacy_message',
    targetId: message.id,
    ip: req.ip,
    metadata: { confirmationsReceived: result.count, confirmationsRequired: result.required },
  });

  if (result.released) {
    const beneficiary = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(message.beneficiary_id);
    logAudit({ action: 'legacy_message.released', targetType: 'legacy_message', targetId: message.id, metadata: { trigger: 'trusted_contact_confirmation' } });
    if (beneficiary && beneficiary.linked_user_id) {
      db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)')
        .run(beneficiary.linked_user_id, 'message_released', `A legacy message titled "${message.title}" has been released to you.`);
    }
  }

  res.json({ message: 'Confirmation recorded', confirmationsReceived: result.count, confirmationsRequired: result.required, released: result.released });
}));

module.exports = router;
