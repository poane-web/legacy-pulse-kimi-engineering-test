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
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

const FAKE_PDF_CONTENT = Buffer.from('%PDF-1.4\nPDF-LIKE-CONTENT-1234');

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
      .attach('file', FAKE_PDF_CONTENT, { filename: 'will.pdf', contentType: 'application/pdf' });

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

  // V2.0-B regression test for finding H4 (docs/V2_SECURITY_AUDIT.md):
  // V1 only checked the client-supplied Content-Type header, so a file
  // whose actual bytes are plain HTML/script content but declared as an
  // allowed type (e.g. application/pdf) would have been accepted and
  // stored. It must now be rejected based on real content inspection.
  test('rejects a file whose content does not match its declared (spoofed) MIME type', async () => {
    const maliciousButDeclaredPdf = Buffer.from('<html><body><script>alert(document.cookie)</script></body></html>');
    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', maliciousButDeclaredPdf, { filename: 'totally-a-pdf.pdf', contentType: 'application/pdf' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/does not match/i);
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
    expect(Buffer.compare(res.body, FAKE_PDF_CONTENT)).toBe(0);
  });

  test('another user cannot download someone else\'s document', async () => {
    const otherToken = await registerAndLogin('doc-intruder@example.com');
    const res = await request(app).get(`/api/documents/${documentId}/download`).set('Authorization', `Bearer ${otherToken}`);
    expect(res.status).toBe(403);
  });
});
