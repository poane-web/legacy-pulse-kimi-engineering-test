'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const db = require('../db');
const { verifyTotp } = require('../utils/totp');
const jwt = require('jsonwebtoken');
const config = require('../config/env');

const app = createApp();

async function registerAndLogin(email, password = 'SuperSecret99') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

// Computes a valid current TOTP code for a given base32 secret, for tests
// that need to actually pass verification (as opposed to testing rejection).
function currentCodeFor(secret) {
  // verifyTotp doesn't expose hotp() directly, so brute-force the 6-digit
  // space against verifyTotp with window=0 is impractical; instead
  // require the module's internal function isn't exported, so we
  // replicate the RFC 6238 computation inline for test purposes only.
  const crypto = require('crypto');
  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function base32Decode(encoded) {
    const clean = encoded.toUpperCase().replace(/=+$/, '');
    let bits = '';
    for (const char of clean) bits += BASE32_ALPHABET.indexOf(char).toString(2).padStart(5, '0');
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(bytes);
  }
  const counter = Math.floor(Date.now() / 1000 / 30);
  const key = base32Decode(secret);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binCode % 1000000).padStart(6, '0');
}

describe('V2.0-C / L3: TOTP MFA setup, login-challenge flow, and disable', () => {
  test('MFA is off by default for a new account', async () => {
    const token = await registerAndLogin('mfa-default@example.com');
    const status = await request(app).get('/api/security/mfa/status').set('Authorization', `Bearer ${token}`);
    expect(status.body.enabled).toBe(false);
  });

  test('full setup -> verify-setup -> enabled flow works, and login now requires a second factor', async () => {
    const email = 'mfa-full-flow@example.com';
    const password = 'SuperSecret99';
    const token = await registerAndLogin(email, password);

    const setup = await request(app).post('/api/security/mfa/setup').set('Authorization', `Bearer ${token}`);
    expect(setup.status).toBe(200);
    expect(setup.body.secret).toBeTruthy();
    expect(setup.body.provisioningUri).toMatch(/^otpauth:\/\/totp\//);

    // Not enabled yet — only after verify-setup.
    let status = await request(app).get('/api/security/mfa/status').set('Authorization', `Bearer ${token}`);
    expect(status.body.enabled).toBe(false);

    const code = currentCodeFor(setup.body.secret);
    const verify = await request(app).post('/api/security/mfa/verify-setup').set('Authorization', `Bearer ${token}`).send({ code });
    expect(verify.status).toBe(200);

    status = await request(app).get('/api/security/mfa/status').set('Authorization', `Bearer ${token}`);
    expect(status.body.enabled).toBe(true);

    // Now a normal login does NOT return a usable access token.
    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(login.status).toBe(200);
    expect(login.body.mfaRequired).toBe(true);
    expect(login.body.accessToken).toBeUndefined();
    expect(login.body.challengeToken).toBeTruthy();

    // Completing the second factor issues a real, working access token.
    const secondCode = currentCodeFor(setup.body.secret);
    const mfaVerify = await request(app)
      .post('/api/auth/mfa/verify')
      .set('X-Legacy-Pulse-Client', '1')
      .send({ challengeToken: login.body.challengeToken, code: secondCode });
    expect(mfaVerify.status).toBe(200);
    expect(mfaVerify.body.accessToken).toBeTruthy();

    const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${mfaVerify.body.accessToken}`);
    expect(me.status).toBe(200);
  });

  test('wrong TOTP code is rejected at the login-challenge step', async () => {
    const email = 'mfa-wrong-code@example.com';
    const password = 'SuperSecret99';
    const token = await registerAndLogin(email, password);
    const setup = await request(app).post('/api/security/mfa/setup').set('Authorization', `Bearer ${token}`);
    const code = currentCodeFor(setup.body.secret);
    await request(app).post('/api/security/mfa/verify-setup').set('Authorization', `Bearer ${token}`).send({ code });

    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    const badVerify = await request(app)
      .post('/api/auth/mfa/verify')
      .set('X-Legacy-Pulse-Client', '1')
      .send({ challengeToken: login.body.challengeToken, code: '000000' });
    expect(badVerify.status).toBe(401);
  });

  test('disabling MFA requires the correct password', async () => {
    const email = 'mfa-disable@example.com';
    const password = 'SuperSecret99';
    const token = await registerAndLogin(email, password);
    const setup = await request(app).post('/api/security/mfa/setup').set('Authorization', `Bearer ${token}`);
    const code = currentCodeFor(setup.body.secret);
    await request(app).post('/api/security/mfa/verify-setup').set('Authorization', `Bearer ${token}`).send({ code });

    const wrongPassword = await request(app).post('/api/security/mfa/disable').set('Authorization', `Bearer ${token}`).send({ password: 'wrongpassword' });
    expect(wrongPassword.status).toBe(401);

    const correctPassword = await request(app).post('/api/security/mfa/disable').set('Authorization', `Bearer ${token}`).send({ password });
    expect(correctPassword.status).toBe(200);

    const status = await request(app).get('/api/security/mfa/status').set('Authorization', `Bearer ${token}`);
    expect(status.body.enabled).toBe(false);

    // Login no longer requires a second factor.
    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(login.body.mfaRequired).toBeUndefined();
    expect(login.body.accessToken).toBeTruthy();
  });

  // ---------------------------------------------------------------------
  // Critical security property: an MFA challenge token (issued after only
  // the FIRST factor) must never be usable as a real access token, even
  // though it's a structurally valid JWT signed with the same secret.
  // ---------------------------------------------------------------------
  test('an MFA challenge token cannot be used to access protected routes', async () => {
    const email = 'mfa-challenge-confusion@example.com';
    const password = 'SuperSecret99';
    const token = await registerAndLogin(email, password);
    const setup = await request(app).post('/api/security/mfa/setup').set('Authorization', `Bearer ${token}`);
    const code = currentCodeFor(setup.body.secret);
    await request(app).post('/api/security/mfa/verify-setup').set('Authorization', `Bearer ${token}`).send({ code });

    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(login.body.mfaRequired).toBe(true);

    // Attempt to use the challenge token directly against a protected route.
    const attempt = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${login.body.challengeToken}`);
    expect(attempt.status).toBe(401);
  });

  test('a real access token cannot be used in place of an MFA challenge token', async () => {
    const email = 'mfa-reverse-confusion@example.com';
    const password = 'SuperSecret99';
    const token = await registerAndLogin(email, password);
    const setup = await request(app).post('/api/security/mfa/setup').set('Authorization', `Bearer ${token}`);
    const code = currentCodeFor(setup.body.secret);
    await request(app).post('/api/security/mfa/verify-setup').set('Authorization', `Bearer ${token}`).send({ code });

    // `token` here is a real access token issued before MFA was even
    // enabled (still validly signed). Try to use it as if it were a
    // challenge token against /auth/mfa/verify.
    const attempt = await request(app)
      .post('/api/auth/mfa/verify')
      .set('X-Legacy-Pulse-Client', '1')
      .send({ challengeToken: token, code: currentCodeFor(setup.body.secret) });
    expect(attempt.status).toBe(401);
    expect(attempt.body.error.message).toMatch(/invalid or expired mfa challenge/i);
  });

  test('an expired/garbage challenge token is rejected', async () => {
    const garbage = jwt.sign({ sub: 1, typ: 'mfa_challenge' }, 'wrong-secret-entirely', { expiresIn: '5m' });
    const res = await request(app).post('/api/auth/mfa/verify').set('X-Legacy-Pulse-Client', '1').send({ challengeToken: garbage, code: '123456' });
    expect(res.status).toBe(401);
  });

  test('setup cannot be started twice while already enabled', async () => {
    const email = 'mfa-double-setup@example.com';
    const password = 'SuperSecret99';
    const token = await registerAndLogin(email, password);
    const setup = await request(app).post('/api/security/mfa/setup').set('Authorization', `Bearer ${token}`);
    const code = currentCodeFor(setup.body.secret);
    await request(app).post('/api/security/mfa/verify-setup').set('Authorization', `Bearer ${token}`).send({ code });

    const secondSetup = await request(app).post('/api/security/mfa/setup').set('Authorization', `Bearer ${token}`);
    expect(secondSetup.status).toBe(400);
  });
});

describe('V2.0-C / L3: TOTP algorithm correctness against RFC 6238 official test vectors', () => {
  test('matches RFC 6238 Appendix B vectors (truncated to 6 digits)', () => {
    function base32Encode(buffer) {
      const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = '';
      for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
      let output = '';
      for (let i = 0; i + 5 <= bits.length; i += 5) output += ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
      const remainder = bits.length % 5;
      if (remainder !== 0) output += ALPHABET[parseInt(bits.slice(bits.length - remainder).padEnd(5, '0'), 2)];
      return output;
    }
    const secret = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
    const originalNow = Date.now;

    // RFC 6238 8-digit vectors, truncated to their last 6 digits (mathematically
    // equal to the 6-digit HOTP truncation at the same counter).
    const vectors = [
      { t: 59, expected8: '94287082' },
      { t: 1111111109, expected8: '07081804' },
      { t: 1234567890, expected8: '89005924' },
    ];
    for (const { t, expected8 } of vectors) {
      Date.now = () => t * 1000;
      const expected6 = expected8.slice(-6);
      expect(verifyTotp(secret, expected6, 0)).toBe(true);
    }
    Date.now = originalNow;
  });

  test('rejects a code outside the tolerance window', () => {
    function base32Encode(buffer) {
      const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = '';
      for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
      let output = '';
      for (let i = 0; i + 5 <= bits.length; i += 5) output += ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
      return output;
    }
    const secret = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
    const originalNow = Date.now;
    Date.now = () => 59 * 1000;
    // A code from far outside the ±1 step window must be rejected.
    expect(verifyTotp(secret, '000000', 1)).toBe(false);
    Date.now = originalNow;
  });

  test('rejects malformed (non-6-digit) codes outright', () => {
    expect(verifyTotp('JBSWY3DPEHPK3PXP', 'abcdef')).toBe(false);
    expect(verifyTotp('JBSWY3DPEHPK3PXP', '12345')).toBe(false);
    expect(verifyTotp('JBSWY3DPEHPK3PXP', '')).toBe(false);
  });
});
