'use strict';

// V3-PG Step 2: explicit result-compatibility tests, run against REAL
// PostgreSQL (not mocked, not SQLite). Requires PGHOST/PGUSER/PGPASSWORD/
// PGDATABASE env vars pointing at a database with schema.pg.sql already
// applied. If those env vars aren't set, every test in this file is
// skipped (not silently passed) -- see the guard below.
//
// This file tests the ADAPTER itself in isolation, against real
// PostgreSQL. It does not yet exercise route/service code -- that's
// Step 6. This is "VERIFIED -- database invariant only" evidence for the
// adapter's own correctness, not an application-security claim.

const hasPgEnv = process.env.PGHOST && process.env.PGUSER && process.env.PGPASSWORD && process.env.PGDATABASE;
const describeIfPg = hasPgEnv ? describe : describe.skip;

const INSERT_USER = "INSERT INTO users (email, password_hash, full_name) VALUES (?, ?, ?)";

describeIfPg('Postgres adapter: result compatibility (real PostgreSQL required)', () => {
  let db;

  beforeAll(() => {
    const { createPostgresDb } = require('../adapter');
    db = createPostgresDb();
  });

  afterAll(async () => {
    await db.close();
  });

  beforeEach(async () => {
    await db.exec('TRUNCATE users, beneficiaries, trusted_contacts, legacy_messages, release_confirmations, notifications, audit_logs RESTART IDENTITY CASCADE');
  });

  test('SELECT with .get() returns a single row object, or undefined when no match', async () => {
    await db.prepare(INSERT_USER).run('a@example.com', 'hash', 'Test User');
    const row = await db.prepare('SELECT * FROM users WHERE email = ?').get('a@example.com');
    expect(row.email).toBe('a@example.com');

    const missing = await db.prepare('SELECT * FROM users WHERE email = ?').get('nobody@example.com');
    expect(missing).toBeUndefined();
  });

  test('SELECT with .all() returns an array, empty array when no match (not null/undefined)', async () => {
    await db.prepare(INSERT_USER).run('a@example.com', 'hash', 'Test User');
    await db.prepare(INSERT_USER).run('b@example.com', 'hash', 'Test User');
    const rows = await db.prepare('SELECT * FROM users ORDER BY email').all();
    expect(rows.length).toBe(2);
    expect(rows[0].email).toBe('a@example.com');

    const empty = await db.prepare('SELECT * FROM users WHERE email = ?').all('nobody@example.com');
    expect(Array.isArray(empty)).toBe(true);
    expect(empty.length).toBe(0);
  });

  test('INSERT: .run() reports lastInsertRowid via auto-appended RETURNING id, matching better-sqlite3\'s contract', async () => {
    const info = await db.prepare(INSERT_USER).run('c@example.com', 'hash', 'Test User');
    expect(typeof info.lastInsertRowid).toBe('number');
    expect(info.changes).toBe(1);

    const fetched = await db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    expect(fetched.email).toBe('c@example.com');
  });

  test('UPDATE: .run() reports affected-row count via .changes, 0 when no row matched', async () => {
    const info = await db.prepare(INSERT_USER).run('d@example.com', 'hash', 'Test User');
    const updated = await db.prepare('UPDATE users SET full_name = ? WHERE id = ?').run('New Name', info.lastInsertRowid);
    expect(updated.changes).toBe(1);

    const noMatch = await db.prepare('UPDATE users SET full_name = ? WHERE id = ?').run('Nobody', 999999);
    expect(noMatch.changes).toBe(0);
  });

  test('DELETE: .run() reports affected-row count via .changes', async () => {
    const info = await db.prepare(INSERT_USER).run('e@example.com', 'hash', 'Test User');
    const deleted = await db.prepare('DELETE FROM users WHERE id = ?').run(info.lastInsertRowid);
    expect(deleted.changes).toBe(1);

    const stillThere = await db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    expect(stillThere).toBeUndefined();
  });

  test('NULL values round-trip correctly (not coerced to empty string or 0)', async () => {
    const info = await db.prepare(INSERT_USER).run('f@example.com', 'hash', 'Test User');
    const row = await db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    expect(row.mfa_secret_encrypted).toBeNull();
    expect(row.locked_until).toBeNull();
  });

  test('boolean column (mfa_enabled): stored/retrieved as real boolean, not 0/1 integer', async () => {
    const info = await db.prepare('INSERT INTO users (email, password_hash, full_name, mfa_enabled) VALUES (?, ?, ?, ?)')
      .run('g@example.com', 'hash', 'Test User', true);
    const row = await db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    expect(row.mfa_enabled).toBe(true);
    expect(typeof row.mfa_enabled).toBe('boolean');
  });

  test('timestamp columns are normalized to ISO-8601 strings, matching the SQLite path\'s format', async () => {
    const info = await db.prepare(INSERT_USER).run('h@example.com', 'hash', 'Test User');
    const row = await db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    expect(typeof row.created_at).toBe('string');
    expect(row.created_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  test('a literal ? inside a stored string value is preserved correctly through insert and read-back (placeholder translation applied at the SQL level, not the data level)', async () => {
    const info = await db.prepare(INSERT_USER).run('i@example.com', 'hash', "What's this? A test!");
    const row = await db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    expect(row.full_name).toBe("What's this? A test!");
  });

  test('CHECK constraint violation throws with Postgres\'s check_violation code (23514)', async () => {
    await expect(
      db.prepare("INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, 'superadmin')").run('j@example.com', 'hash', 'Test User')
    ).rejects.toMatchObject({ code: '23514' });
  });

  test('UNIQUE constraint violation throws with Postgres\'s unique_violation code (23505)', async () => {
    await db.prepare(INSERT_USER).run('dup@example.com', 'hash', 'Test User');
    await expect(
      db.prepare(INSERT_USER).run('dup@example.com', 'hash', 'Test User')
    ).rejects.toMatchObject({ code: '23505' });
  });

  test('FOREIGN KEY violation throws with Postgres\'s foreign_key_violation code (23503)', async () => {
    await expect(
      db.prepare('INSERT INTO beneficiaries (owner_id, full_name, email) VALUES (?, ?, ?)').run(999999, 'Nobody', 'nobody@example.com')
    ).rejects.toMatchObject({ code: '23503' });
  });

  test('named @param placeholders (utils/audit.js style) work end-to-end against real Postgres', async () => {
    const user = await db.prepare(INSERT_USER).run('k@example.com', 'hash', 'Test User');
    const insertStmt = db.prepare(
      'INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, metadata_json) VALUES (@actor_user_id, @action, @target_type, @target_id, @metadata_json)'
    );
    await insertStmt.run({ actor_user_id: user.lastInsertRowid, action: 'test.action', target_type: 'user', target_id: user.lastInsertRowid, metadata_json: null });
    const row = await db.prepare('SELECT * FROM audit_logs WHERE actor_user_id = ?').get(user.lastInsertRowid);
    expect(row.action).toBe('test.action');
    expect(row.metadata_json).toBeNull();
  });

  test('db.transaction: a committed transaction persists all its writes', async () => {
    const run = db.transaction(async (txDb) => {
      const u1 = await txDb.prepare(INSERT_USER).run('tx1@example.com', 'hash', 'Test User');
      const u2 = await txDb.prepare(INSERT_USER).run('tx2@example.com', 'hash', 'Test User');
      return { u1: u1.lastInsertRowid, u2: u2.lastInsertRowid };
    });
    await run();

    const rows = await db.prepare('SELECT * FROM users WHERE email IN (?, ?)').all('tx1@example.com', 'tx2@example.com');
    expect(rows.length).toBe(2);
  });

  test('db.transaction: rolls back ALL writes if any statement throws, even ones already "succeeded" earlier in the same transaction', async () => {
    const run = db.transaction(async (txDb) => {
      await txDb.prepare(INSERT_USER).run('rollback-test@example.com', 'hash', 'Test User');
      await txDb.prepare("INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, 'not-a-real-role')")
        .run('rollback-test-2@example.com', 'hash', 'Test User');
    });

    await expect(run()).rejects.toBeTruthy();

    const row = await db.prepare('SELECT * FROM users WHERE email = ?').get('rollback-test@example.com');
    expect(row).toBeUndefined(); // proves the rollback actually happened, not just that an error was thrown
  });
});
