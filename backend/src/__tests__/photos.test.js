'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');

const app = createApp();

async function registerAndLogin(email, password = 'SuperSecret99') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

// A minimal, valid 1x1 PNG (real magic bytes + a plausible tail).
const REAL_PNG = Buffer.from(
  '89504e470d0a1a0a0000000d49484452000000010000000108020000009077' +
  '53de0000000c4944415478da6360000002000155a8b6ba0000000049454e44ae426082',
  'hex'
);

describe('Photo upload/download (V2.0-B coverage)', () => {
  let token;
  let photoId;

  beforeAll(async () => {
    token = await registerAndLogin('photo-owner@example.com');
  });

  test('uploads a real PNG successfully', async () => {
    const res = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .field('caption', 'A real photo')
      .attach('file', REAL_PNG, { filename: 'photo.png', contentType: 'image/png' });
    expect(res.status).toBe(201);
    photoId = res.body.photo.id;
  });

  // V2.0-B regression test for finding H4 (docs/V2_SECURITY_AUDIT.md):
  // photos are served INLINE (no Content-Disposition: attachment), unlike
  // documents, making content-type spoofing a more direct risk here.
  test('rejects a file whose content does not match its declared image type', async () => {
    const notActuallyAnImage = Buffer.from('<script>alert(1)</script>');
    const res = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', notActuallyAnImage, { filename: 'fake.png', contentType: 'image/png' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/does not match/i);
  });

  test('rejects a real PNG mislabeled as a different allowed image type (JPEG)', async () => {
    const res = await request(app)
      .post('/api/photos')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', REAL_PNG, { filename: 'mislabeled.jpg', contentType: 'image/jpeg' });
    expect(res.status).toBe(400);
  });

  test('downloads the photo back correctly and logs the download (V2.0-B finding M4)', async () => {
    const res = await request(app)
      .get(`/api/photos/${photoId}/download`)
      .set('Authorization', `Bearer ${token}`)
      .buffer(true)
      .parse((response, callback) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => callback(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    expect(Buffer.compare(res.body, REAL_PNG)).toBe(0);

    const auditRes = await request(app).get('/api/audit/me').set('Authorization', `Bearer ${token}`);
    expect(auditRes.body.logs.some((l) => l.action === 'photo.downloaded' && l.targetId === photoId)).toBe(true);
  });

  test('another user cannot download someone else\'s photo', async () => {
    const otherToken = await registerAndLogin('photo-intruder@example.com');
    const res = await request(app).get(`/api/photos/${photoId}/download`).set('Authorization', `Bearer ${otherToken}`);
    expect(res.status).toBe(403);
  });
});
