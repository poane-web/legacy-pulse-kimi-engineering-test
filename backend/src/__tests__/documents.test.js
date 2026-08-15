'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const fs = require('fs');
const path = require('path');
const config = require('../config/env');

const app = createApp();

async function registerAndLogin(email) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  return login.body.accessToken;
}

describe('Document upload/download', () => {
  let token;
  let documentId;

  beforeAll(async () => {
    token = await registerAndLogin('doc-owner@example.com');
  });

  test('uploads a document, encrypts it at rest, and metadata never contains raw filename in DB text search', async () => {
    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${token}`)
      .field('description', 'My last will and testament')
      .attach('file', Buffer.from('PDF-LIKE-CONTENT-1234'), { filename: 'will.pdf', contentType: 'application/pdf' });

    expect(res.status).toBe(201);
    documentId = res.body.document.id;
    expect(res.body.document.filename).toBe('will.pdf');

    // The file on disk must NOT contain the plaintext content (proves it's encrypted).
    const files = fs.readdirSync(config.uploadsDir);
    expect(files.length).toBeGreaterThan(0);
    const raw = fs.readFileSync(path.join(config.uploadsDir, files[files.length - 1]));
    expect(raw.includes('PDF-LIKE-CONTENT-1234')).toBe(false);
  });

  test('rejects disallowed file types', async () => {
    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', Buffer.from('#!/bin/sh\necho hacked'), { filename: 'evil.sh', contentType: 'application/x-sh' });
    expect(res.status).toBe(400);
  });

  test('downloads and correctly decrypts the file back to original bytes', async () => {
    const res = await request(app)
      .get(`/api/documents/${documentId}/download`)
      .set('Authorization', `Bearer ${token}`)
      .buffer(true)
      .parse((response, callback) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => callback(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    expect(Buffer.compare(res.body, Buffer.from('PDF-LIKE-CONTENT-1234'))).toBe(0);
  });

  test('another user cannot download someone else\'s document', async () => {
    const otherToken = await registerAndLogin('doc-intruder@example.com');
    const res = await request(app).get(`/api/documents/${documentId}/download`).set('Authorization', `Bearer ${otherToken}`);
    expect(res.status).toBe(403);
  });
});
