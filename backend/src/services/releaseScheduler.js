'use strict';

const cron = require('node-cron');
const db = require('../db');
const { logAudit } = require('../utils/audit');

function runReleaseSweep() {
  const now = new Date().toISOString();
  const due = db.prepare(
    "SELECT id, beneficiary_id, title FROM legacy_messages WHERE status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ?"
  ).all(now);

  // The status predicate is part of the write, not merely the discovery
  // query. Two scheduler workers can therefore observe the same due row, but
  // only one can transition it from pending -> released.
  const release = db.prepare(
    "UPDATE legacy_messages SET status = 'released', released_at = ? WHERE id = ? AND status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ?"
  );
  const notify = db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)');

  let released = 0;
  for (const msg of due) {
    const result = release.run(now, msg.id, now);
    if (result.changes !== 1) continue;

    logAudit({ action: 'legacy_message.released', targetType: 'legacy_message', targetId: msg.id, metadata: { trigger: 'scheduled_date' } });
    const beneficiary = db.prepare('SELECT * FROM beneficiaries WHERE id = ?').get(msg.beneficiary_id);
    if (beneficiary && beneficiary.linked_user_id) {
      notify.run(beneficiary.linked_user_id, 'message_released', `A legacy message titled "${msg.title}" has been released to you.`);
    }
    released += 1;
  }
  return released;
}

function startReleaseScheduler() {
  // Every minute. The transition itself is atomic, so overlapping workers do
  // not duplicate the release or notification.
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
