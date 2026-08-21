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
const { NotFoundError, BadRequestError, ConflictError } = require('../utils/errors');

const router = express.Router();

function toDTO(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    relationship: row.relationship,
    inviteStatus: row.invite_status,
    linked: !!row.linked_user_id,
    createdAt: row.created_at,
  };
}

router.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const rows = db.prepare('SELECT * FROM beneficiaries WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json({ beneficiaries: rows.map(toDTO) });
  })
);

router.post(
  '/',
  requireAuth,
  [
    body('fullName').trim().isLength({ min: 1, max: 200 }),
    body('email').isEmail().normalizeEmail(),
    body('relationship').optional().isString().isLength({ max: 100 }),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { fullName, email, relationship } = req.body;
    const rawInviteToken = randomToken(24);
    const tokenHash = sha256Hex(rawInviteToken);

    const info = db.prepare(
      'INSERT INTO beneficiaries (owner_id, full_name, email, relationship, invite_token_hash) VALUES (?, ?, ?, ?, ?)'
    ).run(req.user.id, fullName, email, relationship || null, tokenHash);

    logAudit({ actorUserId: req.user.id, action: 'beneficiary.created', targetType: 'beneficiary', targetId: info.lastInsertRowid, ip: req.ip });

    const row = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({
      beneficiary: toDTO(row),
      inviteLink: `/claim-invite?type=beneficiary&token=${rawInviteToken}&email=${encodeURIComponent(email)}`,
    });
  })
);

router.put(
  '/:id',
  requireAuth,
  requireOwnership((req) => db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(req.params.id), 'beneficiary'),
  [
    body('fullName').optional().trim().isLength({ min: 1, max: 200 }),
    body('relationship').optional().isString().isLength({ max: 100 }),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { fullName, relationship } = req.body;
    db.prepare('UPDATE beneficiaries SET full_name = COALESCE(?, full_name), relationship = COALESCE(?, relationship) WHERE id = ?')
      .run(fullName ?? null, relationship ?? null, req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'beneficiary.updated', targetType: 'beneficiary', targetId: Number(req.params.id), ip: req.ip });
    res.json({ beneficiary: toDTO(db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(req.params.id)) });
  })
);

router.delete(
  '/:id',
  requireAuth,
  requireOwnership((req) => db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(req.params.id), 'beneficiary'),
  asyncHandler(async (req, res) => {
    // legacy_messages currently reference beneficiaries with ON DELETE CASCADE.
    // Deleting a beneficiary therefore used to silently destroy both pending
    // and already-released legacy messages. A released legacy record is an
    // irreversible historical commitment and must outlive relationship
    // management changes. Refuse deletion while any message references it.
    const dependent = db.prepare('SELECT COUNT(*) AS count FROM legacy_messages WHERE beneficiary_id = ?').get(req.params.id);
    if (dependent.count > 0) {
      throw new ConflictError('Beneficiary cannot be deleted while legacy messages reference it; revoke or replace the relationship instead');
    }

    db.prepare('DELETE FROM beneficiaries WHERE id = ? AND owner_id = ?').run(req.params.id, req.user.id);
    logAudit({ actorUserId: req.user.id, action: 'beneficiary.revoked', targetType: 'beneficiary', targetId: Number(req.params.id), ip: req.ip });
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
    const row = db.prepare('SELECT * FROM beneficiaries WHERE invite_token_hash = ? AND invite_status = ?').get(tokenHash, 'pending');
    if (!row) throw new NotFoundError('Invite not found or already used');
    if (row.email.toLowerCase() !== req.user.email.toLowerCase()) {
      throw new BadRequestError('This invite was issued to a different email address');
    }
    db.prepare('UPDATE beneficiaries SET linked_user_id = ?, invite_status = ?, invite_token_hash = NULL WHERE id = ?')
      .run(req.user.id, 'claimed', row.id);
    logAudit({ actorUserId: req.user.id, action: 'beneficiary.invite_claimed', targetType: 'beneficiary', targetId: row.id, ip: req.ip });
    res.json({ message: 'Invite claimed. You can now view legacy messages addressed to you once released.' });
  })
);

module.exports = router;
