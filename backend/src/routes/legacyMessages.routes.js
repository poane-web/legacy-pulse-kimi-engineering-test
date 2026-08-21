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

function normalizeReleaseAt(value) {
  if (value === undefined || value === null) return value;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new BadRequestError('releaseAt must be a valid ISO-8601 timestamp');
  return parsed.toISOString();
}

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

router.get('/', asyncHandler(async (req, res) => {
  const rows = db.prepare('SELECT * FROM legacy_messages WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json({ messages: rows.map(ownerDTO) });
}));

router.post('/', [
  body('beneficiaryId').isInt(),
  body('title').trim().isLength({ min: 1, max: 300 }),
  body('body').isString().isLength({ min: 1, max: 50000 }),
  body('releaseType').isIn(['scheduled_date', 'trusted_contact_confirmation', 'immediate']),
  body('releaseAt').optional({ nullable: true }).isISO8601(),
], handleValidation, asyncHandler(async (req, res) => {
  const { beneficiaryId, title, body: msgBody, releaseType, releaseAt } = req.body;

  const beneficiary = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(beneficiaryId);
  if (!beneficiary || beneficiary.owner_id !== req.user.id) {
    throw new BadRequestError('Invalid beneficiaryId');
  }
  if (releaseType === 'scheduled_date' && !releaseAt) {
    throw new BadRequestError('releaseAt is required when releaseType is scheduled_date');
  }

  const normalizedReleaseAt = releaseType === 'scheduled_date' ? normalizeReleaseAt(releaseAt) : null;
  const isImmediate = releaseType === 'immediate';

  // Immediate release is a single durable state transition. The message,
  // recipient snapshot, audit event, and in-app notification must commit or
  // roll back together. Otherwise a process crash between INSERT and
  // notification could create a released message with no durable notice.
  const createAndRelease = db.transaction(() => {
    const releasedAt = isImmediate ? new Date().toISOString() : null;
    const info = db.prepare(
      `INSERT INTO legacy_messages
        (owner_id, beneficiary_id, title, body_encrypted, release_type, release_at, status, released_at, released_recipient_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      req.user.id,
      beneficiaryId,
      title,
      encryptField(msgBody),
      releaseType,
      normalizedReleaseAt,
      isImmediate ? 'released' : 'pending',
      releasedAt,
      isImmediate ? beneficiary.linked_user_id : null
    );

    logAudit({ actorUserId: req.user.id, action: 'legacy_message.created', targetType: 'legacy_message', targetId: info.lastInsertRowid, ip: req.ip });

    if (isImmediate && beneficiary.linked_user_id) {
      db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)')
        .run(beneficiary.linked_user_id, 'message_released', `A legacy message titled "${title}" has been released to you.`);
    }

    return info;
  });

  const info = createAndRelease();
  res.status(201).json({ message: ownerDTO(db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(info.lastInsertRowid)) });
}));

router.put('/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id), 'legacy_message'),
  [
    body('title').optional().trim().isLength({ min: 1, max: 300 }),
    body('body').optional().isString().isLength({ min: 1, max: 50000 }),
    body('releaseAt').optional({ nullable: true }).isISO8601(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    if (req.resource.status !== 'pending') throw new BadRequestError('Only pending (not yet released) messages can be edited');
    if (req.body.releaseAt === null && req.resource.release_type === 'scheduled_date') throw new BadRequestError('Scheduled messages must retain a releaseAt timestamp');

    const { title, body: msgBody, releaseAt } = req.body;
    const normalizedReleaseAt = releaseAt !== undefined ? normalizeReleaseAt(releaseAt) : undefined;
    const result = db.prepare(
      `UPDATE legacy_messages SET
        title = COALESCE(?, title),
        body_encrypted = COALESCE(?, body_encrypted),
        release_at = COALESCE(?, release_at),
        config_version = config_version + 1
       WHERE id = ? AND owner_id = ? AND status = 'pending' AND config_version = ?`
    ).run(title ?? null, msgBody !== undefined ? encryptField(msgBody) : null, normalizedReleaseAt ?? null, req.params.id, req.user.id, req.resource.config_version);

    if (result.changes !== 1) throw new BadRequestError('Message was released or changed before this update could be applied');
    logAudit({ actorUserId: req.user.id, action: 'legacy_message.updated', targetType: 'legacy_message', targetId: Number(req.params.id), ip: req.ip });
    res.json({ message: ownerDTO(db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id)) });
  })
);

router.delete('/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id), 'legacy_message'),
  asyncHandler(async (req, res) => {
    if (req.resource.status !== 'pending') throw new BadRequestError('Only pending (not yet released) messages can be deleted');
    const result = db.prepare("DELETE FROM legacy_messages WHERE id = ? AND owner_id = ? AND status = 'pending'").run(req.params.id, req.user.id);
    if (result.changes !== 1) throw new BadRequestError('Message was released before it could be deleted');
    logAudit({ actorUserId: req.user.id, action: 'legacy_message.deleted', targetType: 'legacy_message', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

router.get('/inbox', asyncHandler(async (req, res) => {
  const rows = db.prepare(`SELECT lm.* FROM legacy_messages lm WHERE lm.released_recipient_user_id = ? AND lm.status = 'released' ORDER BY lm.released_at DESC`).all(req.user.id);
  res.json({ messages: rows.map((row) => ({ id: row.id, title: row.title, releasedAt: row.released_at })) });
}));

router.get('/:id/read', asyncHandler(async (req, res) => {
  const row = db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(req.params.id);
  if (!row) throw new NotFoundError('Message not found');
  const isAddressedToCaller = row.released_recipient_user_id === req.user.id;
  if (!isAddressedToCaller || row.status !== 'released') {
    logAudit({ actorUserId: req.user.id, action: 'legacy_message.unauthorized_access_attempt', targetType: 'legacy_message', targetId: row.id, ip: req.ip, metadata: { reason: !isAddressedToCaller ? 'not_release_recipient' : 'not_yet_released' } });
    throw new ForbiddenError('This message is not available to you');
  }
  logAudit({ actorUserId: req.user.id, action: 'legacy_message.read', targetType: 'legacy_message', targetId: row.id, ip: req.ip });
  res.json({ message: { id: row.id, title: row.title, body: decryptField(row.body_encrypted), releasedAt: row.released_at } });
}));

module.exports = router;
