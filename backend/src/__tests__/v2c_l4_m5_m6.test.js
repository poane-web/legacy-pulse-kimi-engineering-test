'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const db = require('../db');
const config = require('../config/env');

const app = createApp();

async function registerAndLogin(email, password = 'SuperSecret99') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

// ---------------------------------------------------------------------
// L4 regression (docs/V2_SECURITY_AUDIT.md, Low; docs/V2_0_C_PLAN.md §2):
// account-level lockout after repeated failed logins, layered on top of
// the existing IP rate limiter.
// ---------------------------------------------------------------------
describe('V2.0-C / L4: account lockout after repeated failed logins', () => {
  test('locks the account after the configured threshold and rejects even the correct password while locked', async () => {
    const email = 'lockout-test@example.com';
    const correctPassword = 'CorrectPass99';
    await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password: correctPassword, fullName: 'Lockout Test' });

    for (let i = 0; i < config.accountLockoutThreshold; i++) {
      const res = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password: 'wrongpassword' });
      expect(res.status).toBe(401);
    }

    // Even the CORRECT password is now rejected because the account is locked.
    const lockedAttempt = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password: correctPassword });
    expect(lockedAttempt.status).toBe(401);
    expect(lockedAttempt.body.error.message).toMatch(/temporarily locked/i);
  });

  test('a successful login resets the failed-attempt counter', async () => {
    const email = 'lockout-reset@example.com';
    const password = 'CorrectPass99';
    await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: 'Reset Test' });

    await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password: 'wrong1' });
    await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password: 'wrong2' });
    const success = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(success.status).toBe(200);

    const user = db.prepare('SELECT failed_login_count, locked_until FROM users WHERE email = ?').get(email);
    expect(user.failed_login_count).toBe(0);
    expect(user.locked_until).toBeNull();
  });

  test('the lock expires after the configured duration (simulated by directly expiring it)', async () => {
    const email = 'lockout-expiry@example.com';
    const password = 'CorrectPass99';
    await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: 'Expiry Test' });

    for (let i = 0; i < config.accountLockoutThreshold; i++) {
      await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password: 'wrong' });
    }
    const locked = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(locked.status).toBe(401);

    // Simulate time passing by moving locked_until into the past directly.
    db.prepare('UPDATE users SET locked_until = ? WHERE email = ?').run(new Date(Date.now() - 1000).toISOString(), email);

    const afterExpiry = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(afterExpiry.status).toBe(200);
  });

  test('failed attempts against a nonexistent email do not error or crash (no user row to update)', async () => {
    const res = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: 'never-registered@example.com', password: 'whatever123' });
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------
// M5 regression (docs/V2_SECURITY_AUDIT.md, Medium): trust proxy is now
// an explicit, documented setting rather than an implicit default.
// ---------------------------------------------------------------------
describe('V2.0-C / M5: explicit trust-proxy policy', () => {
  test('the app does not trust X-Forwarded-For by default (req.ip is the real socket peer)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('X-Legacy-Pulse-Client', '1')
      .set('X-Forwarded-For', '1.2.3.4') // attacker-supplied, must be ignored
      .send({ email: 'trustproxy-test@example.com', password: 'wrongpassword' });
    expect(res.status).toBe(401);

    const log = db.prepare("SELECT ip_address FROM audit_logs WHERE action = 'auth.login_failed' ORDER BY id DESC LIMIT 1").get();
    // The spoofed IP must NOT have been recorded — proves X-Forwarded-For was ignored.
    expect(log.ip_address).not.toBe('1.2.3.4');
  });
});

// ---------------------------------------------------------------------
// M6 regression (docs/V2_SECURITY_AUDIT.md, Medium): refresh_tokens
// cleanup script only removes dead (revoked/expired) rows, never a live one.
// ---------------------------------------------------------------------
describe('V2.0-C / M6: refresh_tokens retention cleanup', () => {
  test('removes revoked tokens older than the retention window, leaves everything else alone', async () => {
    const { cleanupRefreshTokens } = require('../db/cleanup');
    const email = 'cleanup-test@example.com';
    await registerAndLogin(email);
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);

    const oldRevokedDate = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString(); // 40 days ago
    const recentRevokedDate = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(); // 5 days ago
    const futureExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked_at) VALUES (?, ?, ?, ?)')
      .run(user.id, 'old-dead-token-hash', futureExpiry, oldRevokedDate);
    db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked_at) VALUES (?, ?, ?, ?)')
      .run(user.id, 'recent-dead-token-hash', futureExpiry, recentRevokedDate);
    db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked_at) VALUES (?, ?, ?, NULL)')
      .run(user.id, 'live-token-hash', futureExpiry);

    const deletedCount = cleanupRefreshTokens(30);
    expect(deletedCount).toBe(1); // only the 40-day-old revoked one

    const remaining = db.prepare('SELECT token_hash FROM refresh_tokens WHERE user_id = ?').all(user.id).map((r) => r.token_hash);
    expect(remaining).not.toContain('old-dead-token-hash');
    expect(remaining).toContain('recent-dead-token-hash');
    expect(remaining).toContain('live-token-hash');
  });
});
