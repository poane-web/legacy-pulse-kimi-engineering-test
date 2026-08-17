// V2.0-D (docs/V2_0_D_PLAN.md, audit findings H2/H3): the single, shared
// module that owns the legacy_messages `pending -> released` state
// transition. Both the cron sweep and the trusted-contact confirmation
// flow call into this instead of maintaining their own inline release
// logic, so the atomicity/idempotency guarantees below apply everywhere a
// message can be released, not just in whichever code path someone
// remembered to be careful in.
'use strict';

const db = require('../db');
const config = require('../config/env');
const { logAudit } = require('../utils/audit');

/**
 * Releases a single message, if (and only if) it is still 'pending'.
 * Atomic: status update, notification insert, and audit log all happen in
 * one db.transaction() -- if anything throws, EVERYTHING rolls back, so a
 * message can never end up half-released (e.g. status flipped but no
 * notification sent). Idempotent: re-checks `WHERE status = 'pending'` at
 * transaction time, so calling this twice for the same message (from two
 * different trigger points, or a retried sweep) is a safe no-op the
 * second time, not a duplicate release/notification.
 *
 * @param {number} messageId
 * @param {'scheduled_date'|'trusted_contact_confirmation'} trigger
 * @returns {boolean} true if this call actually released the message,
 *   false if it was already released (or didn't exist) and nothing happened.
 */
function releaseMessage(messageId, trigger) {
  const run = db.transaction(() => {
    const now = new Date().toISOString();
    const updateResult = db.prepare(
      "UPDATE legacy_messages SET status = 'released', released_at = ? WHERE id = ? AND status = 'pending'"
    ).run(now, messageId);

    if (updateResult.changes === 0) {
      // Already released (or doesn't exist) — nothing to do. Not an error;
      // this is the idempotency guard working as intended.
      return false;
    }

    const message = db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(messageId);
    logAudit({ action: 'legacy_message.released', targetType: 'legacy_message', targetId: messageId, metadata: { trigger } });

    const beneficiary = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(message.beneficiary_id);
    if (beneficiary && beneficiary.linked_user_id) {
      db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)')
        .run(beneficiary.linked_user_id, 'message_released', `A legacy message titled "${message.title}" has been released to you.`);
    }
    return true;
  });
  return run();
}

/** Number of distinct trusted contacts who have confirmed this owner's release-trigger event. */
function confirmationsMet(ownerId) {
  const count = db.prepare('SELECT COUNT(*) AS c FROM release_confirmations WHERE owner_id = ?').get(ownerId).c;
  return count >= config.requiredReleaseConfirmations;
}

/**
 * Releases every currently-pending trusted_contact_confirmation message
 * for `ownerId`, IF the confirmation threshold has been met. Safe to call
 * defensively/redundantly (see docs/V2_0_D_PLAN.md) — a no-op if the
 * threshold isn't met, and each individual release is independently
 * idempotent via releaseMessage's own guard.
 *
 * Called from two places (this is the H3 fix): when a new confirmation is
 * submitted (trustedContacts.routes.js), AND when a new
 * trusted_contact_confirmation message is created (legacyMessages.routes.js)
 * — covering the case where the threshold was already met before the
 * message even existed.
 */
function attemptReleaseTrustedContactMessages(ownerId) {
  if (!confirmationsMet(ownerId)) return 0;
  const pending = db.prepare(
    "SELECT id FROM legacy_messages WHERE owner_id = ? AND release_type = 'trusted_contact_confirmation' AND status = 'pending'"
  ).all(ownerId);
  let released = 0;
  for (const row of pending) {
    if (releaseMessage(row.id, 'trusted_contact_confirmation')) released += 1;
  }
  return released;
}

/** Releases every currently-due scheduled_date message, across all owners. */
function attemptReleaseScheduledMessages() {
  const now = new Date().toISOString();
  const due = db.prepare(
    "SELECT id FROM legacy_messages WHERE status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ?"
  ).all(now);
  let released = 0;
  for (const row of due) {
    if (releaseMessage(row.id, 'scheduled_date')) released += 1;
  }
  return released;
}

module.exports = { releaseMessage, confirmationsMet, attemptReleaseTrustedContactMessages, attemptReleaseScheduledMessages };
