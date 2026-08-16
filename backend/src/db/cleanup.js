// V2.0-C (docs/V2_0_C_PLAN.md §5, audit finding M6): deletes refresh_tokens
// rows that are BOTH revoked-or-expired AND older than a retention window,
// so the table doesn't grow unboundedly forever under normal use.
//
// Deliberately conservative: only ever touches rows that are already dead
// weight (revoked or past their expiry), never a currently-valid session.
// Run manually via `npm run cleanup`, or wire into a scheduled job in a
// real deployment (deferred to V2.0-F — this script existing is not the
// same as it being scheduled).
//
// audit_logs is intentionally NOT purged here: its retention needs are a
// compliance/product decision (how long should account activity history
// be kept?), not a mechanical "delete old rows" default this script
// should make unilaterally. Flagged as a V2.0-F production-readiness item.
'use strict';

const db = require('./index');
const config = require('./../config/env');

function cleanupRefreshTokens(retentionDays = 30) {
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const result = db.prepare(
    `DELETE FROM refresh_tokens
     WHERE (revoked_at IS NOT NULL AND revoked_at < ?)
        OR (expires_at < ?)`
  ).run(cutoff, cutoff);
  return result.changes;
}

module.exports = { cleanupRefreshTokens };

if (require.main === module) {
  const retentionDays = parseInt(process.env.REFRESH_TOKEN_RETENTION_DAYS || '30', 10);
  const deleted = cleanupRefreshTokens(retentionDays);
  console.log(`[cleanup] removed ${deleted} expired/revoked refresh token row(s) older than ${retentionDays} days`);
  process.exit(0);
}
