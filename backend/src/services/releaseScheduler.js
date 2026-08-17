// Background worker that releases scheduled-date legacy messages once
// their release_at time has passed. Runs every minute via node-cron.
//
// V2.0-D (docs/V2_0_D_PLAN.md): the actual release logic now lives in
// services/legacyMessageRelease.js, the single shared module for the
// pending->released transition. This file is just the cron wiring.
'use strict';

const cron = require('node-cron');
const { attemptReleaseScheduledMessages } = require('./legacyMessageRelease');

function runReleaseSweep() {
  return attemptReleaseScheduledMessages();
}

function startReleaseScheduler() {
  // Every minute. Safe to overlap/retry: attemptReleaseScheduledMessages
  // -> releaseMessage is idempotent per-message (see legacyMessageRelease.js).
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
