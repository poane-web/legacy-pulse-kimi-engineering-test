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
const { requireStepUpPassword } = require('../middleware/requireStepUpPassword');

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
    // NOTE (documented simplification, see docs/THREAT_MODEL.md): no email
    // delivery integration exists in this MVP. The raw invite token/link is
    // returned here only to the Owner who just created the invite, standing
    // in for "an email was sent". It must never be exposed to anyone else.
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
  // V3 follow-up (docs/security/V3-THREAT-MODEL.md, category G step-up
  // gap): deleting a beneficiary affects release authority (who can
  // receive released content) -- now requires password re-confirmation,
  // in addition to the V3-H2 guard against destroying released content.
  requireStepUpPassword(),
  asyncHandler(async (req, res) => {
    // V3 SECURITY FIX (docs/security/V3-THREAT-MODEL.md, finding V3-H2):
    // legacy_messages.beneficiary_id is ON DELETE CASCADE, meaning V1/V2
    // let an owner delete a beneficiary and, with no warning at all,
    // silently and permanently destroy every legacy message addressed to
    // them -- INCLUDING already-released ones the beneficiary may have
    // already read or been notified about. This directly conflicts with
    // the product's core promise that released content reaches its
    // recipient reliably. Retroactively destroying already-released
    // content is arguably worse than merely losing access to it.
    //
    // Fixed at the application layer (not by changing the FK's ON DELETE
    // behavior, which would need a full table rebuild in SQLite -- see
    // the precedent in docs/V2_0_E_PLAN.md for why that's avoided where
    // an equally-correct application-layer check exists): block deletion
    // outright if the beneficiary has any released messages. The owner
    // must not be able to make already-delivered content disappear.
    const releasedCount = db.prepare(
      "SELECT COUNT(*) AS c FROM legacy_messages WHERE beneficiary_id = ? AND status = 'released'"
    ).get(req.params.id).c;
    if (releasedCount > 0) {
      throw new ConflictError(
        `Cannot remove this beneficiary: they have ${releasedCount} already-released legacy message(s). ` +
        'Released content cannot be retroactively destroyed. Delete the individual message(s) first if you understand the consequences, or contact support.'
      );
    }

    db.prepare('DELETE FROM beneficiaries WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'beneficiary.deleted', targetType: 'beneficiary', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

// A beneficiary claims their invite by registering/logging in separately
// via /auth/register, then calling this to link their new user account to
// the beneficiary record. Kept as a distinct explicit step (rather than
// matching purely by email) so a beneficiary must possess the invite token.
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
    // V3 SECURITY FIX (docs/security/V3-THREAT-MODEL.md, finding
    // V3-H1): the UPDATE below now re-checks invite_status='pending' in
    // its WHERE clause and verifies exactly one row was affected, instead
    // of relying solely on the earlier SELECT check. Under SQLite's
    // single-process serialized execution the original check-then-act
    // pattern was harmless; under a real multi-worker Postgres deployment,
    // two concurrent requests racing on the same invite token could both
    // pass the initial SELECT before either's UPDATE committed, producing
    // a duplicate 'claimed' transition and a duplicate audit log entry for
    // what should be a single event. This is now a single atomic
    // conditional UPDATE, the same pattern already used in
    // services/legacyMessageRelease.js.
    const updateResult = db.prepare(
      "UPDATE beneficiaries SET linked_user_id = ?, invite_status = 'claimed', invite_token_hash = NULL WHERE id = ? AND invite_status = 'pending'"
    ).run(req.user.id, row.id);
    if (updateResult.changes === 0) {
      throw new ConflictError('This invite has already been claimed');
    }
    logAudit({ actorUserId: req.user.id, action: 'beneficiary.invite_claimed', targetType: 'beneficiary', targetId: row.id, ip: req.ip });
    res.json({ message: 'Invite claimed. You can now view legacy messages addressed to you once released.' });
  })
);

module.exports = router;
