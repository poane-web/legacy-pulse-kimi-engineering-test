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
const config = require('../config/env');
const { attemptReleaseTrustedContactMessages } = require('../services/legacyMessageRelease');

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

// V3 (docs/security/V3-THREAT-MODEL.md, finding V3-M3): V1/V2 gave the
// owner NO way to see whether their account currently has any recorded
// release-trigger confirmations -- confirmations never expire and are
// only ever cleared by revoking the confirming trusted contact entirely.
// A mistaken or malicious pair of confirmations left an owner's account
// silently "primed": any future trusted_contact_confirmation message they
// created would auto-release immediately (the V2.0-D H3 fix), with no way
// for the owner to notice this state existed. This endpoint at least
// makes that state visible and inspectable; it does not add expiry or a
// one-click reset, which are flagged as deferred follow-ups in
// docs/security/V3-PRODUCTION-READINESS.md.
router.get(
  '/confirmation-status',
  requireAuth,
  asyncHandler(async (req, res) => {
    const confirmations = db.prepare(
      `SELECT rc.confirmed_at, tc.full_name, tc.email
       FROM release_confirmations rc
       JOIN trusted_contacts tc ON tc.id = rc.trusted_contact_id
       WHERE rc.owner_id = ?
       ORDER BY rc.confirmed_at ASC`
    ).all(req.user.id);
    res.json({
      confirmationsReceived: confirmations.length,
      confirmationsRequired: config.requiredReleaseConfirmations,
      primed: confirmations.length >= config.requiredReleaseConfirmations,
      confirmations: confirmations.map((c) => ({ confirmedAt: c.confirmed_at, trustedContactName: c.full_name, trustedContactEmail: c.email })),
    });
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
    // V2.0-B SECURITY FIX (docs/V2_SECURITY_AUDIT.md, finding C2 -- Critical):
    // V1 was missing this check entirely, meaning anyone who obtained the
    // raw invite token (link leakage, forwarding, interception) could claim
    // trusted-contact status under ANY account, regardless of whether they
    // were the person the Owner actually intended. Trusted contacts are
    // half of the two-person release-trigger rule (docs/ARCHITECTURE.md
    // §6), so this previously let a single attacker undermine that control
    // by self-assigning as one of the two required confirmers. Mirrors the
    // equivalent (and already-correct) check in beneficiaries.routes.js.
    if (row.email.toLowerCase() !== req.user.email.toLowerCase()) {
      logAudit({
        actorUserId: req.user.id,
        action: 'trusted_contact.claim_email_mismatch',
        targetType: 'trusted_contact',
        targetId: row.id,
        ip: req.ip,
      });
      throw new BadRequestError('This invite was issued to a different email address');
    }
    // V3 SECURITY FIX (docs/security/V3-THREAT-MODEL.md, finding V3-H1):
    // same atomic-conditional-update fix as beneficiaries.routes.js — see
    // that file's comment for the full rationale.
    const updateResult = db.prepare(
      "UPDATE trusted_contacts SET linked_user_id = ?, status = 'active', invite_token_hash = NULL WHERE id = ? AND status = 'pending'"
    ).run(req.user.id, row.id);
    if (updateResult.changes === 0) {
      throw new ConflictError('This invite has already been claimed');
    }
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

    // V3 SECURITY FIX (docs/security/V3-THREAT-MODEL.md, finding V3-M1):
    // the check above and this INSERT are two separate statements. Under
    // SQLite's single-process serialized execution, two requests from the
    // same trusted contact can't actually interleave between them (no
    // `await` boundary exists in this handler); under a real multi-worker
    // Postgres deployment they genuinely could, and the second INSERT
    // would then hit the UNIQUE(owner_id, trusted_contact_id) constraint
    // as a raw, uncaught database error -- propagating as an unhandled
    // 500 instead of the clean 409 the pre-check was meant to guarantee.
    // The UNIQUE constraint itself was always the real data-integrity
    // guarantee (a duplicate confirmation could never actually be
    // persisted); this fix only makes the error response correct.
    try {
      db.prepare('INSERT INTO release_confirmations (owner_id, trusted_contact_id) VALUES (?, ?)').run(ownerId, contact.id);
    } catch (err) {
      // SQLite's constraint error code today; '23505' is Postgres's
      // unique_violation code, included so this still works correctly if
      // this app is ever ported to Postgres (see
      // docs/security/V3-PRODUCTION-READINESS.md) without anyone having to
      // remember to update this check.
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || err.code === 'SQLITE_CONSTRAINT' || err.code === '23505') {
        throw new ConflictError('You have already submitted a confirmation for this account');
      }
      throw err;
    }
    logAudit({ actorUserId: req.user.id, action: 'trusted_contact.confirmation_submitted', targetType: 'user', targetId: ownerId, ip: req.ip });

    const count = db.prepare('SELECT COUNT(*) AS c FROM release_confirmations WHERE owner_id = ?').get(ownerId).c;
    const required = config.requiredReleaseConfirmations;

    // V2.0-D (docs/V2_0_D_PLAN.md, audit finding H2): release is now
    // handled by the shared, transactional legacyMessageRelease module —
    // each message's status update + notification + audit log happen
    // atomically, and a failure releasing one message no longer risks
    // leaving another half-released. See that module for the full
    // atomicity/idempotency guarantees.
    attemptReleaseTrustedContactMessages(ownerId);

    res.json({ message: 'Confirmation recorded', confirmationsReceived: count, confirmationsRequired: required });
  })
);

module.exports = router;
