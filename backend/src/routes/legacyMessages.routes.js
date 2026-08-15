'use strict';

const express = require('express');
const { body } = require('express-validator');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { requireOwnership } = require('../middleware/rbac');
const { handleValidation } = require('../middleware/validate');
const { logAudit } = require('../utils/audit');
const { encryptField, decryptField } = require('../utils/crypto');
const { BadRequestError, ForbiddenError, NotFoundError } = require('../utils/errors');

const router = express.Router();
router.use(requireAuth);

function ownerDTO(row) {
  return {
    id: row.id,
    beneficiaryId: row.beneficiary_id,
    title: row.title,
    body: decryptField(row.body_encrypted),
    releaseType: row.release_type,
    releaseAt: row.release_at,
    requiredConfirmations: row.required_confirmations,
    status: row.status,
    releasedAt: row.released_at,
    createdAt: row.created_at,
  };
}

// ---- Owner: list/create/update/delete own authored messages -------------
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const rows = db.prepare('SELECT * FROM legacy_messages WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json({ messages: rows.map(ownerDTO) });
  })
);

router.post(
  '/',
  [
    body('beneficiaryId').isInt(),
    body('title').trim().isLength({ min: 1, max: 300 }),
    body('body').isString().isLength({ min: 1, max: 50000 }),
    body('releaseType').isIn(['scheduled_date', 'trusted_contact_confirmation', 'immediate']),
    body('releaseAt').optional({ nullable: true }).isISO8601(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { beneficiaryId, title, body: msgBody, releaseType, releaseAt } = req.body;

    const beneficiary = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(beneficiaryId);
    if (!beneficiary || beneficiary.owner_id !== req.user.id) {
      throw new BadRequestError('Invalid beneficiaryId');
    }
    if (releaseType === 'scheduled_date' && !releaseAt) {
      throw new BadRequestError('releaseAt is required when releaseType is scheduled_date');
    }

    const isImmediate = releaseType === 'immediate';
    const info = db.prepare(
      `INSERT INTO legacy_messages
        (owner_id, beneficiary_id, title, body_encrypted, release_type, release_at, status, released_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      req.user.id,
      beneficiaryId,
      title,
      encryptField(msgBody),
      releaseType,
      releaseType === 'scheduled_date' ? releaseAt : null,
      isImmediate ? 'released' : 'pending',
      isImmediate ? new Date().toISOString() : null
    );

    logAudit({ actorUserId: req.user.id, action: 'legacy_message.created', targetType: 'legacy_message', targetId: info.lastInsertRowid, ip: req.ip });

    if (isImmediate && beneficiary.linked_user_id) {
      db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)')
        .run(beneficiary.linked_user_id, 'message_released', `A legacy message titled "${title}" has been released to you.`);
    }

    res.status(201).json({ message: ownerDTO(db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(info.lastInsertRowid)) });
  })
);

router.put(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id), 'legacy_message'),
  [
    body('title').optional().trim().isLength({ min: 1, max: 300 }),
    body('body').optional().isString().isLength({ min: 1, max: 50000 }),
    body('releaseAt').optional({ nullable: true }).isISO8601(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    if (req.resource.status !== 'pending') {
      throw new BadRequestError('Only pending (not yet released) messages can be edited');
    }
    const { title, body: msgBody, releaseAt } = req.body;
    db.prepare(
      `UPDATE legacy_messages SET
        title = COALESCE(?, title),
        body_encrypted = COALESCE(?, body_encrypted),
        release_at = COALESCE(?, release_at)
       WHERE id = ?`
    ).run(title ?? null, msgBody !== undefined ? encryptField(msgBody) : null, releaseAt ?? null, req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'legacy_message.updated', targetType: 'legacy_message', targetId: Number(req.params.id), ip: req.ip });
    res.json({ message: ownerDTO(db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id)) });
  })
);

router.delete(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id), 'legacy_message'),
  asyncHandler(async (req, res) => {
    if (req.resource.status !== 'pending') {
      throw new BadRequestError('Only pending (not yet released) messages can be deleted');
    }
    db.prepare('DELETE FROM legacy_messages WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'legacy_message.deleted', targetType: 'legacy_message', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

// ---- Beneficiary: inbox of released messages addressed to them ----------
router.get(
  '/inbox',
  asyncHandler(async (req, res) => {
    const rows = db.prepare(
      `SELECT lm.* FROM legacy_messages lm
       JOIN beneficiaries b ON b.id = lm.beneficiary_id
       WHERE b.linked_user_id = ? AND lm.status = 'released'
       ORDER BY lm.released_at DESC`
    ).all(req.user.id);
    res.json({
      messages: rows.map((row) => ({
        id: row.id,
        title: row.title,
        releasedAt: row.released_at,
        // Body intentionally omitted from the list view; fetched only via
        // the single-message read endpoint below, which re-checks
        // authorization and writes an audit entry for the read itself.
      })),
    });
  })
);

router.get(
  '/:id/read',
  asyncHandler(async (req, res) => {
    const row = db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id);
    if (!row) throw new NotFoundError('Message not found');

    const beneficiary = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(row.beneficiary_id);
    const isAddressedToCaller = beneficiary && beneficiary.linked_user_id === req.user.id;

    if (!isAddressedToCaller || row.status !== 'released') {
      logAudit({
        actorUserId: req.user.id,
        action: 'legacy_message.unauthorized_access_attempt',
        targetType: 'legacy_message',
        targetId: row.id,
        ip: req.ip,
        metadata: { reason: !isAddressedToCaller ? 'not_addressed_to_caller' : 'not_yet_released' },
      });
      // Same response for "not yours" and "not released yet" — avoids
      // confirming existence/ownership details to a probing caller.
      throw new ForbiddenError('This message is not available to you');
    }

    logAudit({ actorUserId: req.user.id, action: 'legacy_message.read', targetType: 'legacy_message', targetId: row.id, ip: req.ip });
    res.json({
      message: {
        id: row.id,
        title: row.title,
        body: decryptField(row.body_encrypted),
        releasedAt: row.released_at,
      },
    });
  })
);

module.exports = router;
