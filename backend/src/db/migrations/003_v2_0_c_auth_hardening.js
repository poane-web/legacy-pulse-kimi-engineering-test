// V2.0-C (docs/V2_0_C_PLAN.md): account lockout columns + a format marker
// on documents/photos so existing (V1, no-AAD) encrypted files continue to
// decrypt correctly once storage.js starts supporting the AAD-bound v2
// format for newly-uploaded files. Safe for both fresh and existing DBs.
'use strict';

function addColumnIfMissing(db, table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info('${table}')`).all();
  if (!columns.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

module.exports = {
  name: '003_v2_0_c_auth_hardening',
  up(db) {
    addColumnIfMissing(db, 'users', 'failed_login_count', 'INTEGER NOT NULL DEFAULT 0');
    addColumnIfMissing(db, 'users', 'locked_until', 'TEXT');
    addColumnIfMissing(db, 'documents', 'enc_format', "TEXT NOT NULL DEFAULT 'v1'");
    addColumnIfMissing(db, 'photos', 'enc_format', "TEXT NOT NULL DEFAULT 'v1'");
  },
};
