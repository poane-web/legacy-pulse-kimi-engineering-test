'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const db = require('../db');

const app = createApp();

async function registerAndLogin(email, password = 'SuperSecret9') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

// ---------------------------------------------------------------------
// H1 regression (docs/V2_SECURITY_AUDIT.md, High): V1's requireAuth was
// pure JWT verification with no DB check, so an access token issued
// before a password change / admin-disable / "sign out everywhere"
// remained fully valid until its natural <=15min expiry. It must now be
// rejected on its very next use after any of those events.
// ---------------------------------------------------------------------
describe('V2.0-B / H1: access tokens are invalidated by security-relevant events', () => {
  test('changing password invalidates the previously-issued access token immediately', async () => {
    const email = 'h1-password-change@example.com';
    const password = 'OldSecurePass9';
    const oldAccessToken = await registerAndLogin(email, password);

    const beforeChange = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${oldAccessToken}`);
    expect(beforeChange.status).toBe(200);

    const changeRes = await request(app)
      .put('/api/users/password')
      .set('Authorization', `Bearer ${oldAccessToken}`)
      .send({ currentPassword: password, newPassword: 'BrandNewPass9' });
    expect(changeRes.status).toBe(200);

    // The OLD access token — still cryptographically valid and unexpired —
    // must now be rejected because token_version was bumped server-side.
    const afterChange = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${oldAccessToken}`);
    expect(afterChange.status).toBe(401);

    // A fresh login with the new password gets a token that DOES work.
    const relogin = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password: 'BrandNewPass9' });
    const afterRelogin = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${relogin.body.accessToken}`);
    expect(afterRelogin.status).toBe(200);
  });

  test('admin disabling a user invalidates that user\'s already-issued access token immediately', async () => {
    const targetEmail = 'h1-disable-target@example.com';
    const targetToken = await registerAndLogin(targetEmail);

    const adminEmail = 'h1-disable-admin@example.com';
    const adminPassword = 'AdminPass9';
    await registerAndLogin(adminEmail, adminPassword);
    db.prepare("UPDATE users SET role = 'admin' WHERE email = ?").run(adminEmail);
    const adminLogin = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: adminEmail, password: adminPassword });
    const adminToken = adminLogin.body.accessToken;

    const beforeDisable = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${targetToken}`);
    expect(beforeDisable.status).toBe(200);

    const targetUser = db.prepare('SELECT id FROM users WHERE email = ?').get(targetEmail);
    const disableRes = await request(app)
      .put(`/api/admin/users/${targetUser.id}/status`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'disabled' });
    expect(disableRes.status).toBe(200);

    const afterDisable = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${targetToken}`);
    expect(afterDisable.status).toBe(401);
  });

  test('"sign out everywhere" invalidates the calling device\'s own access token too, not just other devices\' refresh tokens', async () => {
    const email = 'h1-revoke-all@example.com';
    const token = await registerAndLogin(email);

    const before = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(before.status).toBe(200);

    const revoke = await request(app).post('/api/security/sessions/revoke-all').set('Authorization', `Bearer ${token}`);
    expect(revoke.status).toBe(200);

    const after = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(after.status).toBe(401);
  });

  test('a disabled account cannot obtain a new access token via login', async () => {
    const email = 'h1-disabled-login@example.com';
    const password = 'SomePass99';
    await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: 'Disabled User' });
    db.prepare("UPDATE users SET status = 'disabled' WHERE email = ?").run(email);

    const res = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(res.status).toBe(401);
  });

  test('a token from before this migration (no tokenVersion claim) is treated as version 0, not rejected outright', async () => {
    // Simulates an access token issued by the pre-V2.0-B code, which had
    // no tokenVersion claim at all. New users start at token_version=0, so
    // a JWT missing the claim (defaulted to 0 in middleware/auth.js) must
    // still work against a freshly-registered, never-touched account.
    const jwt = require('jsonwebtoken');
    const config = require('../config/env');
    const email = 'h1-legacy-token@example.com';
    await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password: 'SomePass99', fullName: 'Legacy Token User' });
    const user = db.prepare('SELECT id, role, email FROM users WHERE email = ?').get(email);

    const legacyStyleToken = jwt.sign({ sub: user.id, role: user.role, email: user.email }, config.jwtAccessSecret, { expiresIn: '15m' });
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${legacyStyleToken}`);
    expect(res.status).toBe(200);
  });
});
