// Background worker that releases scheduled-date legacy messages once
// their release_at time has passed. Runs every minute via node-cron.
// Extracted as a pure function (`runReleaseSweep`) so it's unit-testable
// without waiting on a real cron tick.
'use strict';

const cron = require('node-cron');
const db = require('../db');
const { logAudit } = require('../utils/audit');

function runReleaseSweep() {
  const now = new Date().toISOString();
  const due = db.prepare(
    "SELECT * FROM legacy_messages WHERE status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ?"
  ).all(now);

  const release = db.prepare("UPDATE legacy_messages SET status = 'released', released_at = ? WHERE id = ?");
  const notify = db.prepare('INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)');

  let released = 0;
  for (const msg of due) {
    release.run(now, msg.id);
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
  // Every minute. Idempotent (a message already 'released' won't match the
  // WHERE clause again), so overlapping runs are harmless.
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
