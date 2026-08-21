'use strict';

const cron = require('node-cron');
const db = require('../db');
const { logAudit } = require('../utils/audit');

function runReleaseSweep() {
  const now = new Date().toISOString();
  const due = db.prepare(
    "SELECT id, config_version FROM legacy_messages WHERE status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ?"
  ).all(now);

  const releaseAndNotify = db.transaction((candidate) => {
    // The candidate carries the configuration version observed by discovery.
    // If the owner edits the release configuration before the claim, this
    // conditional update loses the race and NOTHING is released. This prevents
    // a scheduler from releasing a mixed old/new configuration.
    const result = db.prepare(
      "UPDATE legacy_messages SET status = 'released', released_at = ?, released_recipient_user_id = (SELECT linked_user_id FROM beneficiaries WHERE beneficiaries.id = legacy_messages.beneficiary_id) WHERE id = ? AND status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ? AND config_version = ?"
    ).run(now, candidate.id, now, candidate.config_version);
    if (result.changes !== 1) return false;

    // Re-read AFTER the atomic claim. Notifications and audit metadata must be
    // derived from exactly the configuration that won the release claim, never
    // from a stale discovery snapshot.
    const msg = db.prepare('SELECT id, title, beneficiary_id, released_recipient_user_id FROM legacy_messages WHERE id = ?').get(candidate.id);
    if (!msg) throw new Error('Released message disappeared before notification');

    if (msg.released_recipient_user_id) {
      db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)').run(
        msg.released_recipient_user_id,
        'message_released',
        `A legacy message titled "${msg.title}" has been released to you.`
      );
    }

    logAudit({
      action: 'legacy_message.released',
      targetType: 'legacy_message',
      targetId: msg.id,
      metadata: {
        trigger: 'scheduled_date',
        configVersion: candidate.config_version,
        recipientUserId: msg.released_recipient_user_id || null,
      },
    });
    return true;
  });

  let released = 0;
  for (const candidate of due) {
    if (releaseAndNotify(candidate)) released += 1;
  }
  return released;
}

function startReleaseScheduler() {
  // Every minute. Release + recipient snapshot + notification + audit commit
  // atomically, so overlapping workers and transient notification failures
  // cannot leave a message permanently marked released without its durable
  // side effects.
  return cron.schedule('* * * * *', () => {
    try {
      runReleaseSweep();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[releaseScheduler] sweep failed', err);
    }
  });
}

module.exports = { startReleaseScheduler, runReleaseSweep };