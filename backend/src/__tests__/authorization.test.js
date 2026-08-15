'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');

const app = createApp();

async function registerAndLogin(email) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

describe('Authorization: ownership enforcement (IDOR protection)', () => {
  let tokenA;
  let tokenB;
  let memoryIdOwnedByA;

  beforeAll(async () => {
    tokenA = await registerAndLogin('owner-a@example.com');
    tokenB = await registerAndLogin('owner-b@example.com');

    const created = await request(app)
      .post('/api/memories')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ type: 'memory', title: "A's private memory", content: 'Only A should read this.' });
    memoryIdOwnedByA = created.body.memory.id;
  });

  test('owner can read their own memory', async () => {
    const res = await request(app).get(`/api/memories/${memoryIdOwnedByA}`).set('Authorization', `Bearer ${tokenA}`);
    expect(res.status).toBe(200);
    expect(res.body.memory.content).toBe('Only A should read this.');
  });

  test('a different owner CANNOT read it (403, not silently allowed)', async () => {
    const res = await request(app).get(`/api/memories/${memoryIdOwnedByA}`).set('Authorization', `Bearer ${tokenB}`);
    expect(res.status).toBe(403);
  });

  test('a different owner CANNOT delete it', async () => {
    const res = await request(app).delete(`/api/memories/${memoryIdOwnedByA}`).set('Authorization', `Bearer ${tokenB}`);
    expect(res.status).toBe(403);

    // still exists for the real owner
    const check = await request(app).get(`/api/memories/${memoryIdOwnedByA}`).set('Authorization', `Bearer ${tokenA}`);
    expect(check.status).toBe(200);
  });

  test('requesting a nonexistent resource returns 404, not 403 (no info leak beyond existence)', async () => {
    const res = await request(app).get('/api/memories/999999').set('Authorization', `Bearer ${tokenA}`);
    expect(res.status).toBe(404);
  });
});

describe('Authorization: RBAC (admin-only routes)', () => {
  test('a regular owner cannot access admin stats', async () => {
    const token = await registerAndLogin('regular-user@example.com');
    const res = await request(app).get('/api/admin/stats').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('unauthenticated requests to admin routes are rejected', async () => {
    const res = await request(app).get('/api/admin/stats');
    expect(res.status).toBe(401);
  });
});
