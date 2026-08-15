'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');

const app = createApp();

async function registerAndLogin(email, password = 'SuperSecret9') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

// ---------------------------------------------------------------------
// C2 regression (docs/V2_SECURITY_AUDIT.md, Critical): V1's
// POST /trusted-contacts/claim had no check that the claiming user's email
// matched the invited email — anyone with the raw token could claim
// trusted-contact status under any account. Must now be rejected exactly
// like the (already-correct) beneficiary claim route.
// ---------------------------------------------------------------------
describe('V2.0-B / C2: trusted-contact invite claiming requires matching email', () => {
  test('a user whose email does NOT match the invite cannot claim it', async () => {
    const ownerToken = await registerAndLogin('c2-owner@example.com');
    const create = await request(app)
      .post('/api/trusted-contacts')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Intended Contact', email: 'intended@example.com' });
    expect(create.status).toBe(201);
    const rawToken = create.body.inviteLink.split('token=')[1].split('&')[0];

    // An attacker who obtained the raw token, but registers/logs in with a
    // DIFFERENT email than the one the invite was issued to.
    const attackerToken = await registerAndLogin('c2-attacker@example.com');
    const claim = await request(app)
      .post('/api/trusted-contacts/claim')
      .set('Authorization', `Bearer ${attackerToken}`)
      .send({ token: rawToken });

    expect(claim.status).toBe(400);
    expect(claim.body.error.message).toMatch(/different email/i);

    // The trusted contact must NOT have been linked to the attacker's account.
    const list = await request(app).get('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`);
    expect(list.body.trustedContacts[0].linked).toBe(false);
  });

  test('a user whose email DOES match the invite can still claim it (no functional regression)', async () => {
    const ownerToken = await registerAndLogin('c2-owner2@example.com');
    const create = await request(app)
      .post('/api/trusted-contacts')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Real Contact', email: 'realcontact@example.com' });
    const rawToken = create.body.inviteLink.split('token=')[1].split('&')[0];

    const contactToken = await registerAndLogin('realcontact@example.com');
    const claim = await request(app)
      .post('/api/trusted-contacts/claim')
      .set('Authorization', `Bearer ${contactToken}`)
      .send({ token: rawToken });

    expect(claim.status).toBe(200);
    const list = await request(app).get('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`);
    expect(list.body.trustedContacts[0].linked).toBe(true);
  });

  test('claim email matching is case-insensitive (consistent with the beneficiary claim route)', async () => {
    const ownerToken = await registerAndLogin('c2-owner3@example.com');
    const create = await request(app)
      .post('/api/trusted-contacts')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Case Contact', email: 'CaseSensitive@Example.com' });
    const rawToken = create.body.inviteLink.split('token=')[1].split('&')[0];

    const contactToken = await registerAndLogin('casesensitive@example.com');
    const claim = await request(app)
      .post('/api/trusted-contacts/claim')
      .set('Authorization', `Bearer ${contactToken}`)
      .send({ token: rawToken });
    expect(claim.status).toBe(200);
  });
});

// ---------------------------------------------------------------------
// M2 regression (docs/V2_SECURITY_AUDIT.md, Medium): cookie-authenticated
// auth endpoints now require a custom header as CSRF defense-in-depth,
// which a plain cross-site <form> submission cannot set.
// ---------------------------------------------------------------------
describe('V2.0-B / M2: CSRF header required on /api/auth/* endpoints', () => {
  test('login without the required header is rejected', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'nobody@example.com', password: 'whatever123' });
    expect(res.status).toBe(403);
  });

  test('register without the required header is rejected', async () => {
    const res = await request(app).post('/api/auth/register').send({ email: 'csrf-test@example.com', password: 'SomePass123', fullName: 'CSRF Test' });
    expect(res.status).toBe(403);
  });

  test('refresh without the required header is rejected even with a valid cookie', async () => {
    const email = 'm2-refresh@example.com';
    const password = 'SomePass123';
    await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: 'M2 Test' });
    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    const cookie = login.headers['set-cookie'];

    const res = await request(app).post('/api/auth/refresh').set('Cookie', cookie);
    expect(res.status).toBe(403);
  });

  test('login WITH the required header succeeds (no functional regression)', async () => {
    const email = 'm2-login-ok@example.com';
    const password = 'SomePass123';
    await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: 'M2 OK' });
    const res = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------
// M3 regression (docs/V2_SECURITY_AUDIT.md, Medium): the seed script must
// refuse to run against a database started with NODE_ENV=production
// unless explicitly overridden, since it creates publicly-documented
// credentials.
// ---------------------------------------------------------------------
describe('V2.0-B / M3: seed script refuses to run in production without override', () => {
  test('seed() throws when NODE_ENV=production and ALLOW_PROD_SEED is not set', async () => {
    jest.resetModules();
    const savedEnv = { ...process.env };
    process.env.NODE_ENV = 'production';
    delete process.env.ALLOW_PROD_SEED;
    // Re-require config so config.nodeEnv/config.allowProdSeed reflect the
    // overridden env for this test.
    jest.resetModules();
    // eslint-disable-next-line global-require
    const { seed } = require('../db/seed');
    await expect(seed()).rejects.toThrow(/Refusing to run the demo seed script/);
    process.env = savedEnv;
  });
});
