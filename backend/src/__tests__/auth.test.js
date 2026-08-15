'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');

const app = createApp();

describe('Auth flow', () => {
  const creds = { email: 'alice@example.com', password: 'CorrectHorse9', fullName: 'Alice Owner' };

  test('registers a new user', async () => {
    const res = await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send(creds);
    expect(res.status).toBe(201);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.user.email).toBe(creds.email);
    // password must never be echoed back
    expect(JSON.stringify(res.body)).not.toContain(creds.password);
  });

  test('rejects duplicate registration', async () => {
    const res = await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send(creds);
    expect(res.status).toBe(409);
  });

  test('rejects weak passwords', async () => {
    const res = await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email: 'bob@example.com', password: 'short', fullName: 'Bob' });
    expect(res.status).toBe(400);
  });

  test('logs in with correct credentials and sets a refresh cookie', async () => {
    const res = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: creds.email, password: creds.password });
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.headers['set-cookie'].some((c) => c.startsWith('lp_refresh='))).toBe(true);
    expect(res.headers['set-cookie'].some((c) => /HttpOnly/i.test(c))).toBe(true);
  });

  test('rejects login with wrong password', async () => {
    const res = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: creds.email, password: 'wrongpassword1' });
    expect(res.status).toBe(401);
  });

  test('rejects login for nonexistent user with same error shape (no user enumeration)', async () => {
    const res1 = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: 'nobody@example.com', password: 'whatever123' });
    const res2 = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: creds.email, password: 'wrongpassword1' });
    expect(res1.status).toBe(401);
    expect(res2.status).toBe(401);
    expect(res1.body.error.message).toBe(res2.body.error.message);
  });

  test('GET /auth/me requires a valid access token', async () => {
    const noAuth = await request(app).get('/api/auth/me');
    expect(noAuth.status).toBe(401);

    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: creds.email, password: creds.password });
    const authed = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${login.body.accessToken}`);
    expect(authed.status).toBe(200);
    expect(authed.body.user.email).toBe(creds.email);
  });

  test('rejects a malformed/garbage access token', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer not.a.valid.jwt');
    expect(res.status).toBe(401);
  });

  test('refresh rotates the token and old one becomes unusable', async () => {
    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: creds.email, password: creds.password });
    const cookie = login.headers['set-cookie'];

    const refreshed = await request(app).post('/api/auth/refresh').set('X-Legacy-Pulse-Client', '1').set('Cookie', cookie);
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.accessToken).toBeTruthy();

    // Reusing the OLD cookie should now fail (rotation revoked it).
    const reused = await request(app).post('/api/auth/refresh').set('X-Legacy-Pulse-Client', '1').set('Cookie', cookie);
    expect(reused.status).toBe(401);
  });

  test('logout revokes the refresh token', async () => {
    const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: creds.email, password: creds.password });
    const cookie = login.headers['set-cookie'];

    const logout = await request(app).post('/api/auth/logout').set('X-Legacy-Pulse-Client', '1').set('Cookie', cookie);
    expect(logout.status).toBe(204);

    const refreshAfterLogout = await request(app).post('/api/auth/refresh').set('X-Legacy-Pulse-Client', '1').set('Cookie', cookie);
    expect(refreshAfterLogout.status).toBe(401);
  });

  test('login is rate limited after repeated failures', async () => {
    // Uses its own low limit + fresh app instance so this test is
    // deterministic and doesn't depend on how many other requests earlier
    // tests in this file happened to make.
    jest.resetModules();
    process.env.AUTH_RATE_LIMIT_MAX = '5';
    // eslint-disable-next-line global-require
    const freshCreateApp = require('../app');
    const freshApp = freshCreateApp();

    const attempts = [];
    for (let i = 0; i < 8; i++) {
      attempts.push(await request(freshApp).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email: 'ratelimit@example.com', password: 'wrong' }));
    }
    const statuses = attempts.map((r) => r.status);
    expect(statuses).toContain(429);
    delete process.env.AUTH_RATE_LIMIT_MAX;
  });
});
