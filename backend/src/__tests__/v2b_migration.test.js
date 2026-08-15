'use strict';

// This file deliberately does NOT use testSetup.js's auto-applied schema:
// it needs to construct a database that looks like a V1 (pre-token_version)
// database, then run the real migration script against it, to prove the
// migration is safe for an existing production-shaped database — not just
// a fresh one. See docs/V2_SECURITY_AUDIT.md, finding H1, and
// db/migrations/002_add_token_version.js.
const fs = require('fs');
const path = require('path');
const os = require('os');
const Database = require('better-sqlite3');

describe('V2.0-B: token_version migration is safe for an existing V1 database', () => {
  let dbPath;
  let db;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `legacy-pulse-migration-test-${Date.now()}-${Math.random()}.db`);
    db = new Database(dbPath);
    // A stand-in for a V1 users table: no token_version column.
    db.exec(`
      CREATE TABLE schema_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, applied_at TEXT);
      INSERT INTO schema_migrations (name, applied_at) VALUES ('initial_schema', '2026-01-01T00:00:00.000Z');
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'owner',
        status TEXT NOT NULL DEFAULT 'active'
      );
      INSERT INTO users (email, password_hash, full_name, role, status)
        VALUES ('existing-v1-user@example.com', 'somehash', 'V1 User', 'owner', 'active');
    `);
    db.close();
  });

  afterEach(() => {
    try { fs.unlinkSync(dbPath); } catch (e) { /* ignore */ }
  });

  test('running the migration adds token_version defaulted to 0, without touching existing data', () => {
    const migration = require('../db/migrations/002_add_token_version');
    const conn = new Database(dbPath);
    migration.up(conn);

    const columns = conn.prepare("PRAGMA table_info('users')").all();
    expect(columns.some((c) => c.name === 'token_version')).toBe(true);

    const user = conn.prepare('SELECT * FROM users WHERE email = ?').get('existing-v1-user@example.com');
    expect(user.token_version).toBe(0);
    // Pre-existing columns/data are untouched.
    expect(user.full_name).toBe('V1 User');
    expect(user.password_hash).toBe('somehash');

    conn.close();
  });

  test('running the migration twice (idempotency) does not error or duplicate the column', () => {
    const migration = require('../db/migrations/002_add_token_version');
    const conn = new Database(dbPath);
    migration.up(conn);
    expect(() => migration.up(conn)).not.toThrow();

    const columns = conn.prepare("PRAGMA table_info('users')").all().filter((c) => c.name === 'token_version');
    expect(columns.length).toBe(1);
    conn.close();
  });
});
