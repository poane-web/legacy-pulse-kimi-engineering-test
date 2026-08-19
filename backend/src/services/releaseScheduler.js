'use strict';

const cron = require('node-cron');
const db = require('../db');
const { logAudit } = require('../utils/audit');

function runReleaseSweep() {
  const now = new Date().toISOString();
  const due = db.prepare(
    "SELECT id, beneficiary_id, title FROM legacy_messages WHERE status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ?"
  ).all(now);

  const releaseAndNotify = db.transaction((msg) => {
    // The status predicate is part of the write, not merely the discovery
    // query. Two scheduler workers can observe the same due row, but only
    // one can transition it from pending -> released.
    const result = db.prepare(
      "UPDATE legacy_messages SET status = 'released', released_at = ? WHERE id = ? AND status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ?"
    ).run(now, msg.id, now);
    if (result.changes !== 1) return false;

    const beneficiary = db.prepare('SELECT linked_user_id FROM beneficiaries WHERE id = ?').get(msg.beneficiary_id);
    if (beneficiary && beneficiary.linked_user_id) {
      db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)').run(
        beneficiary.linked_user_id,
        'message_released',
        `A legacy message titled "${msg.title}" has been released to you.`
      );
    }

    // The release audit event is part of the same transaction. The release
    // is not durable unless the notification and audit event are durable too.
    logAudit({
      action: 'legacy_message.released',
      targetType: 'legacy_message',
      targetId: msg.id,
      metadata: { trigger: 'scheduled_date' },
    });
    return true;
  });

  let released = 0;
  for (const msg of due) {
    if (releaseAndNotify(msg)) released += 1;
  }
  return released;
}

function startReleaseScheduler() {
  // Every minute. The release, notification, and audit event commit as one
  // transaction, so overlapping workers and transient notification failures
  // cannot leave a message permanently marked released without its durable
  // notification/audit record.
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
