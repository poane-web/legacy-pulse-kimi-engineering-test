// V2.0-B (docs/V2_SECURITY_AUDIT.md, H1): adds users.token_version, used to
// invalidate already-issued JWT access tokens immediately on password
// change, admin-disable, or "sign out everywhere" — previously only
// refresh tokens were revocable, leaving a stateless access token valid
// for up to its full TTL after any of those events.
//
// Safe to run against:
//  - a brand-new database (schema.sql already defines the column; this
//    migration is a no-op there, detected via PRAGMA table_info)
//  - an existing V1 database that predates this column (adds it, default 0
//    for all existing rows, so nobody is unexpectedly logged out)
'use strict';

module.exports = {
  name: '002_add_token_version',
  up(db) {
    const columns = db.prepare("PRAGMA table_info('users')").all();
    const hasColumn = columns.some((c) => c.name === 'token_version');
    if (!hasColumn) {
      db.exec('ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0');
    }
  },
};
