'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');

const app = createApp();

const REAL_PNG = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108020000009077' +
  '53de0000000c4944415478da6360000002000155a8b6ba0000000049454e44ae426082',
  'hex'
);

async function registerAndLogin(email, password = 'SuperSecret99') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

describe('V2.0-E: photo/memory/life-event attachment integrity', () => {
  let token;
  let memoryId;
  let lifeEventId;

  beforeAll(async () => {
    token = await registerAndLogin('v2e-owner@example.com');
    const memory = await request(app).post('/api/memories').set('Authorization', `Bearer ${token}`)
      .send({ type: 'memory', title: 'A memory', content: 'Some content' });
    memoryId = memory.body.memory.id;
    const event = await request(app).post('/api/timeline').set('Authorization', `Bearer ${token}`)
      .send({ title: 'An event', eventDate: '2020-01-01' });
    lifeEventId = event.body.event.id;
  });

  test('a photo cannot be attached to both a memory and a life event at once', async () => {
    const res = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .field('memoryId', String(memoryId))
      .field('lifeEventId', String(lifeEventId))
      .attach('file', REAL_PNG, { filename: 'photo.png', contentType: 'image/png' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/not both/i);
  });

  test('a photo CAN be attached to just a memory (no regression)', async () => {
    const res = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .field('memoryId', String(memoryId))
      .attach('file', REAL_PNG, { filename: 'photo.png', contentType: 'image/png' });
    expect(res.status).toBe(201);
    expect(res.body.photo.memoryId).toBe(memoryId);
    expect(res.body.photo.lifeEventId).toBeNull();
  });

  test('cannot attach a photo to another owner\'s memory (IDOR check, re-verified with a dedicated test)', async () => {
    const otherToken = await registerAndLogin('v2e-other@example.com');
    const otherMemory = await request(app).post('/api/memories').set('Authorization', `Bearer ${otherToken}`)
      .send({ type: 'memory', title: 'Not yours', content: 'content' });

    const res = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .field('memoryId', String(otherMemory.body.memory.id))
      .attach('file', REAL_PNG, { filename: 'photo.png', contentType: 'image/png' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/invalid memoryid/i);
  });

  test('cannot attach a photo to another owner\'s life event (IDOR check)', async () => {
    const otherToken = await registerAndLogin('v2e-other2@example.com');
    const otherEvent = await request(app).post('/api/timeline').set('Authorization', `Bearer ${otherToken}`)
      .send({ title: 'Not yours', eventDate: '2020-01-01' });

    const res = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .field('lifeEventId', String(otherEvent.body.event.id))
      .attach('file', REAL_PNG, { filename: 'photo.png', contentType: 'image/png' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/invalid lifeeventid/i);
  });

  test('GET /photos?memoryId= returns only photos attached to that memory', async () => {
    const event2 = await request(app).post('/api/timeline').set('Authorization', `Bearer ${token}`)
      .send({ title: 'Second event', eventDate: '2021-01-01' });
    await request(app).post('/api/photos').set('Authorization', `Bearer ${token}`)
      .field('lifeEventId', String(event2.body.event.id))
      .attach('file', REAL_PNG, { filename: 'other.png', contentType: 'image/png' });

    const res = await request(app).get(`/api/photos?memoryId=${memoryId}`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.photos.length).toBeGreaterThan(0);
    expect(res.body.photos.every((p) => p.memoryId === memoryId)).toBe(true);
  });

  test('GET /photos?memoryId= for someone else\'s memory ID is rejected, not silently empty', async () => {
    const otherToken = await registerAndLogin('v2e-other3@example.com');
    const otherMemory = await request(app).post('/api/memories').set('Authorization', `Bearer ${otherToken}`)
      .send({ type: 'memory', title: 'Private', content: 'content' });

    const res = await request(app).get(`/api/photos?memoryId=${otherMemory.body.memory.id}`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
  });

  test('a photo can be re-attached from a memory to a life event without re-uploading', async () => {
    const uploaded = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .field('memoryId', String(memoryId))
      .attach('file', REAL_PNG, { filename: 'reattach.png', contentType: 'image/png' });
    const photoId = uploaded.body.photo.id;
    expect(uploaded.body.photo.memoryId).toBe(memoryId);

    const reattached = await request(app)
      .put(`/api/photos/${photoId}/attachment`)
      .set('Authorization', `Bearer ${token}`)
      .send({ lifeEventId });
    expect(reattached.status).toBe(200);
    expect(reattached.body.photo.memoryId).toBeNull();
    expect(reattached.body.photo.lifeEventId).toBe(lifeEventId);
  });

  test('re-attachment also rejects setting both memoryId and lifeEventId', async () => {
    const uploaded = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', REAL_PNG, { filename: 'unattached.png', contentType: 'image/png' });
    const res = await request(app)
      .put(`/api/photos/${uploaded.body.photo.id}/attachment`)
      .set('Authorization', `Bearer ${token}`)
      .send({ memoryId, lifeEventId });
    expect(res.status).toBe(400);
  });

  test('cannot re-attach someone else\'s photo (ownership check on the photo itself)', async () => {
    const otherToken = await registerAndLogin('v2e-other4@example.com');
    const uploaded = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${otherToken}`)
      .attach('file', REAL_PNG, { filename: 'theirs.png', contentType: 'image/png' });

    const res = await request(app)
      .put(`/api/photos/${uploaded.body.photo.id}/attachment`)
      .set('Authorization', `Bearer ${token}`)
      .send({ memoryId });
    expect(res.status).toBe(403);
  });

  test('a photo can be fully detached (both nulled) via re-attachment', async () => {
    const uploaded = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .field('memoryId', String(memoryId))
      .attach('file', REAL_PNG, { filename: 'to-detach.png', contentType: 'image/png' });

    const detached = await request(app)
      .put(`/api/photos/${uploaded.body.photo.id}/attachment`)
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(detached.status).toBe(200);
    expect(detached.body.photo.memoryId).toBeNull();
    expect(detached.body.photo.lifeEventId).toBeNull();
  });
});
