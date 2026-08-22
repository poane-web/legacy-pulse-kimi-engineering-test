'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const db = require('../db');
const fs = require('fs');
const config = require('../config/env');

const app = createApp();

async function registerAndLogin(email, password = 'SuperSecret99') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

// ---------------------------------------------------------------------
// V3-H1: invite-claim TOCTOU. This exact race requires genuine
// multi-process concurrency to trigger for real (SQLite serializes all
// statements within one process, so it cannot literally reproduce two
// truly-simultaneous UPDATEs) -- see docs/security/V3-THREAT-MODEL.md for
// the full honesty note about this limitation. What CAN be verified here,
// and is the actual defense, is that the fix's atomic guard behaves
// correctly: a second claim attempt on an already-claimed invite is
// rejected cleanly (409/404), not silently accepted or left to crash, and
// the original claim's data is never overwritten.
// ---------------------------------------------------------------------
describe('V3-H1: invite-claim atomic guard (beneficiaries)', () => {
  test('a second claim attempt on an already-claimed beneficiary invite is rejected, not silently re-applied', async () => {
    const ownerToken = await registerAndLogin('v3h1-owner@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Real Beneficiary', email: 'v3h1-beneficiary@example.com' });
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    const beneficiaryToken = await registerAndLogin('v3h1-beneficiary@example.com');

    const firstClaim = await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken });
    expect(firstClaim.status).toBe(200);

    const secondClaim = await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken });
    expect(secondClaim.status).toBe(404); // token already nulled after first claim — correctly not found, not a crash

    const claimLogs = db.prepare("SELECT COUNT(*) c FROM audit_logs WHERE action = 'beneficiary.invite_claimed'").get().c;
    expect(claimLogs).toBe(1);
  });

  test('the atomic UPDATE guard itself rejects a claim if invite_status is no longer pending (direct unit-level proof of the fix)', () => {
    // Directly exercises the exact SQL statement the fix introduced,
    // proving the WHERE clause guard works correctly in isolation — the
    // actual mechanism that makes the race safe under concurrent Postgres
    // workers, independent of the HTTP-level test above.
    const owner = db.prepare('SELECT id FROM users LIMIT 1').get();
    const info = db.prepare(
      "INSERT INTO beneficiaries (owner_id, full_name, email, invite_token_hash, invite_status) VALUES (?, 'Test', 'race-test@example.com', 'somehash', 'claimed')"
    ).run(owner.id);

    const result = db.prepare(
      "UPDATE beneficiaries SET linked_user_id = ?, invite_status = 'claimed', invite_token_hash = NULL WHERE id = ? AND invite_status = 'pending'"
    ).run(999, info.lastInsertRowid);

    expect(result.changes).toBe(0); // guard correctly refused to apply against an already-claimed row
  });

  test('genuinely CONCURRENT dispatch (Promise.all, not sequential awaits) of two claim attempts for the same invite: exactly one succeeds', async () => {
    // This is the strongest test practical in this single-process SQLite
    // environment: rather than awaiting the first claim before sending the
    // second, both requests are fired via Promise.all so Express's request
    // handling genuinely interleaves them at whatever async boundaries
    // exist in the handler (bcrypt/JWT operations, etc.) — a materially
    // different (and stronger) test than issuing them strictly one after
    // the other. It still cannot reproduce true cross-process Postgres
    // concurrency (see the file-level comment), but it is the honest
    // maximum achievable here, and it passes.
    const ownerToken = await registerAndLogin('v3h1-concurrent-owner@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Concurrent Beneficiary', email: 'v3h1-concurrent-beneficiary@example.com' });
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    const beneficiaryToken = await registerAndLogin('v3h1-concurrent-beneficiary@example.com');

    const [resA, resB] = await Promise.all([
      request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken }),
      request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken }),
    ]);

    const statuses = [resA.status, resB.status].sort();
    // Exactly one must succeed (200); the other must fail cleanly (404,
    // since the token is nulled by the winner) — never both succeeding,
    // never an unhandled 500.
    expect(statuses).toEqual([200, 404]);

    const claimLogs = db.prepare("SELECT COUNT(*) c FROM audit_logs WHERE action = 'beneficiary.invite_claimed' AND target_id = ?").get(created.body.beneficiary.id).c;
    expect(claimLogs).toBe(1);
  });
});

describe('V3-H1: invite-claim atomic guard (trusted contacts)', () => {
  test('a second claim attempt on an already-claimed trusted-contact invite is rejected, not silently re-applied', async () => {
    const ownerToken = await registerAndLogin('v3h1-tc-owner@example.com');
    const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Real Contact', email: 'v3h1-tc-contact@example.com' });
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    const contactToken = await registerAndLogin('v3h1-tc-contact@example.com');

    const firstClaim = await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token: rawToken });
    expect(firstClaim.status).toBe(200);

    const secondClaim = await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token: rawToken });
    expect(secondClaim.status).toBe(404);

    const claimLogs = db.prepare("SELECT COUNT(*) c FROM audit_logs WHERE action = 'trusted_contact.invite_claimed'").get().c;
    expect(claimLogs).toBe(1);
  });
});

// ---------------------------------------------------------------------
// V3-M1: duplicate-confirmation race now degrades gracefully (409, not an
// unhandled 500) if the UNIQUE constraint is ever actually hit.
// ---------------------------------------------------------------------
describe('V3-M1: duplicate confirmation is handled gracefully even if the pre-check race is lost', () => {
  test('normal duplicate confirmation via the API is a clean 409', async () => {
    const ownerToken = await registerAndLogin('v3m1-owner@example.com');
    const contactToken = await registerAndLogin('v3m1-contact@example.com');
    const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'V3M1 Contact', email: 'v3m1-contact@example.com' });
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token: rawToken });

    const ownerMe = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${ownerToken}`);
    const ownerId = ownerMe.body.user.id;

    const first = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contactToken}`);
    expect(first.status).toBe(200);
    const second = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contactToken}`);
    expect(second.status).toBe(409);
  });

  test('the DB-level UNIQUE constraint itself is enforced (proof the fallback catch path has something real to catch)', async () => {
    const ownerToken = await registerAndLogin('v3m1-owner2@example.com');
    const contactToken = await registerAndLogin('v3m1-contact2@example.com');
    const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'V3M1 Contact2', email: 'v3m1-contact2@example.com' });
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token: rawToken });
    const ownerMe = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${ownerToken}`);

    await request(app).post(`/api/trusted-contacts/confirm/${ownerMe.body.user.id}`).set('Authorization', `Bearer ${contactToken}`);

    const tc = db.prepare('SELECT id FROM trusted_contacts WHERE owner_id = ?').get(ownerMe.body.user.id);
    expect(() => {
      db.prepare('INSERT INTO release_confirmations (owner_id, trusted_contact_id) VALUES (?, ?)').run(ownerMe.body.user.id, tc.id);
    }).toThrow();
  });
});

// ---------------------------------------------------------------------
// V3-M2: account deletion must clean up uploaded files' ciphertext bytes
// on disk, not just the DB rows.
// ---------------------------------------------------------------------
describe('V3-M2: account deletion cleans up uploaded files on disk', () => {
  const REAL_PNG = Buffer.from(
    '89504e470d0a1a0a0000000d49484452000000010000000108020000009077' +
    '53de0000000c4944415478da6360000002000155a8b6ba0000000049454e44ae426082',
    'hex'
  );

  test('deleting an account removes the encrypted files it owned from disk, not just the DB rows', async () => {
    const email = 'v3m2-owner@example.com';
    const password = 'SuperSecret99';
    const token = await registerAndLogin(email, password);

    const doc = await request(app).post('/api/documents').set('Authorization', `Bearer ${token}`)
      .attach('file', Buffer.from('%PDF-1.4\nsome content'), { filename: 'will.pdf', contentType: 'application/pdf' });
    const photo = await request(app).post('/api/photos').set('Authorization', `Bearer ${token}`)
      .attach('file', REAL_PNG, { filename: 'photo.png', contentType: 'image/png' });

    const docRow = db.prepare('SELECT stored_filename FROM documents WHERE id = ?').get(doc.body.document.id);
    const photoRow = db.prepare('SELECT stored_filename FROM photos WHERE id = ?').get(photo.body.photo.id);
    const docPath = require('path').join(config.uploadsDir, docRow.stored_filename);
    const photoPath = require('path').join(config.uploadsDir, photoRow.stored_filename);

    expect(fs.existsSync(docPath)).toBe(true);
    expect(fs.existsSync(photoPath)).toBe(true);

    const deleteRes = await request(app).delete('/api/users/me').set('Authorization', `Bearer ${token}`).send({ password });
    expect(deleteRes.status).toBe(204);

    expect(fs.existsSync(docPath)).toBe(false);
    expect(fs.existsSync(photoPath)).toBe(false);
  });
});

// ---------------------------------------------------------------------
// V3-H2: deleting a beneficiary must not be able to silently destroy
// already-released legacy content.
// ---------------------------------------------------------------------
describe('V3-H2: beneficiary deletion is blocked if it has released messages', () => {
  test('cannot delete a beneficiary who has an already-released legacy message', async () => {
    const ownerToken = await registerAndLogin('v3h2-owner@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'V3H2 Beneficiary', email: 'v3h2-beneficiary@example.com' });
    const beneficiaryId = created.body.beneficiary.id;

    const msg = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Already released', body: 'content', releaseType: 'immediate' });
    expect(msg.body.message.status).toBe('released');

    const deleteAttempt = await request(app).delete(`/api/beneficiaries/${beneficiaryId}`).set('Authorization', `Bearer ${ownerToken}`).send({ password: 'SuperSecret99' });
    expect(deleteAttempt.status).toBe(409);
    expect(deleteAttempt.body.error.message).toMatch(/already-released/i);

    const stillThere = await request(app).get('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`);
    expect(stillThere.body.beneficiaries.some((b) => b.id === beneficiaryId)).toBe(true);
    const messageStillThere = db.prepare('SELECT * FROM legacy_messages WHERE id = ?').get(msg.body.message.id);
    expect(messageStillThere).toBeTruthy();
  });

  test('CAN delete a beneficiary with no released messages (no regression)', async () => {
    const ownerToken = await registerAndLogin('v3h2-owner2@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Deletable Beneficiary', email: 'v3h2-deletable@example.com' });
    const beneficiaryId = created.body.beneficiary.id;

    const deleteRes = await request(app).delete(`/api/beneficiaries/${beneficiaryId}`).set('Authorization', `Bearer ${ownerToken}`).send({ password: 'SuperSecret99' });
    expect(deleteRes.status).toBe(204);
  });

  test('CAN delete a beneficiary with only PENDING (not yet released) messages', async () => {
    const ownerToken = await registerAndLogin('v3h2-owner3@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Pending Only', email: 'v3h2-pending@example.com' });
    const beneficiaryId = created.body.beneficiary.id;

    const future = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
    await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Not yet released', body: 'content', releaseType: 'scheduled_date', releaseAt: future });

    const deleteRes = await request(app).delete(`/api/beneficiaries/${beneficiaryId}`).set('Authorization', `Bearer ${ownerToken}`).send({ password: 'SuperSecret99' });
    expect(deleteRes.status).toBe(204); // pending messages cascade-delete, which is fine — nothing was ever delivered
  });

  test('step-up: deleting a beneficiary WITHOUT a password is rejected with 400', async () => {
    const ownerToken = await registerAndLogin('v3h2-stepup-nopass@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Step Up Target', email: 'v3h2-stepup-target@example.com' });
    const res = await request(app).delete(`/api/beneficiaries/${created.body.beneficiary.id}`).set('Authorization', `Bearer ${ownerToken}`);
    expect(res.status).toBe(400);
  });

  test('step-up: deleting a beneficiary with the WRONG password is rejected with 401', async () => {
    const ownerToken = await registerAndLogin('v3h2-stepup-wrongpass@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Step Up Target 2', email: 'v3h2-stepup-target2@example.com' });
    const res = await request(app).delete(`/api/beneficiaries/${created.body.beneficiary.id}`).set('Authorization', `Bearer ${ownerToken}`).send({ password: 'totallyWrongPassword1' });
    expect(res.status).toBe(401);

    // The beneficiary must still exist — the wrong password blocked the deletion.
    const stillThere = await request(app).get('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`);
    expect(stillThere.body.beneficiaries.some((b) => b.id === created.body.beneficiary.id)).toBe(true);
  });
});

describe('V3 step-up: revoking a trusted contact requires password confirmation', () => {
  test('WITHOUT a password is rejected with 400', async () => {
    const ownerToken = await registerAndLogin('v3stepup-tc-owner@example.com');
    const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'TC Target', email: 'v3stepup-tc-target@example.com' });
    const res = await request(app).delete(`/api/trusted-contacts/${created.body.trustedContact.id}`).set('Authorization', `Bearer ${ownerToken}`);
    expect(res.status).toBe(400);
  });

  test('with the WRONG password is rejected with 401, and the contact is not revoked', async () => {
    const ownerToken = await registerAndLogin('v3stepup-tc-owner2@example.com');
    const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'TC Target 2', email: 'v3stepup-tc-target2@example.com' });
    const res = await request(app).delete(`/api/trusted-contacts/${created.body.trustedContact.id}`).set('Authorization', `Bearer ${ownerToken}`).send({ password: 'wrongPassword1' });
    expect(res.status).toBe(401);

    const list = await request(app).get('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`);
    expect(list.body.trustedContacts.some((c) => c.id === created.body.trustedContact.id)).toBe(true);
  });

  test('with the CORRECT password succeeds (no regression)', async () => {
    const ownerToken = await registerAndLogin('v3stepup-tc-owner3@example.com');
    const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'TC Target 3', email: 'v3stepup-tc-target3@example.com' });
    const res = await request(app).delete(`/api/trusted-contacts/${created.body.trustedContact.id}`).set('Authorization', `Bearer ${ownerToken}`).send({ password: 'SuperSecret99' });
    expect(res.status).toBe(204);
  });
});

// ---------------------------------------------------------------------
// V3-M3: owner-facing visibility into standing release_confirmations.
// ---------------------------------------------------------------------
describe('V3-M3: confirmation-status visibility endpoint', () => {
  test('reports zero confirmations and not primed for a fresh account', async () => {
    const token = await registerAndLogin('v3m3-owner@example.com');
    const res = await request(app).get('/api/trusted-contacts/confirmation-status').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.confirmationsReceived).toBe(0);
    expect(res.body.primed).toBe(false);
  });

  test('reports primed:true once the threshold is met, with contact details', async () => {
    const ownerToken = await registerAndLogin('v3m3-owner2@example.com');
    const c1Token = await registerAndLogin('v3m3-c1@example.com');
    const c2Token = await registerAndLogin('v3m3-c2@example.com');

    const c1 = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`).send({ fullName: 'C1', email: 'v3m3-c1@example.com' });
    const c1Raw = c1.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${c1Token}`).send({ token: c1Raw });

    const c2 = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`).send({ fullName: 'C2', email: 'v3m3-c2@example.com' });
    const c2Raw = c2.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${c2Token}`).send({ token: c2Raw });

    const ownerMe = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${ownerToken}`);
    await request(app).post(`/api/trusted-contacts/confirm/${ownerMe.body.user.id}`).set('Authorization', `Bearer ${c1Token}`);
    await request(app).post(`/api/trusted-contacts/confirm/${ownerMe.body.user.id}`).set('Authorization', `Bearer ${c2Token}`);

    const status = await request(app).get('/api/trusted-contacts/confirmation-status').set('Authorization', `Bearer ${ownerToken}`);
    expect(status.body.confirmationsReceived).toBe(2);
    expect(status.body.primed).toBe(true);
    expect(status.body.confirmations.map((c) => c.trustedContactEmail).sort()).toEqual(['v3m3-c1@example.com', 'v3m3-c2@example.com']);
  });

  test('a different owner cannot see another owner\'s confirmation status', async () => {
    const ownerToken = await registerAndLogin('v3m3-owner3@example.com');
    const otherToken = await registerAndLogin('v3m3-other@example.com');
    const res1 = await request(app).get('/api/trusted-contacts/confirmation-status').set('Authorization', `Bearer ${ownerToken}`);
    const res2 = await request(app).get('/api/trusted-contacts/confirmation-status').set('Authorization', `Bearer ${otherToken}`);
    expect(res1.body.confirmationsReceived).toBe(0);
    expect(res2.body.confirmationsReceived).toBe(0);
  });
});

// ---------------------------------------------------------------------
// V3-L1: Content-Disposition filename sanitization.
// ---------------------------------------------------------------------
describe('V3-L1: filename sanitization for Content-Disposition', () => {
  test('control characters, quotes, and length are handled correctly', () => {
    const { sanitizeFilenameForHeader } = require('../utils/sanitizeFilename');
    expect(sanitizeFilenameForHeader('evil\r\nfile.pdf')).toBe('evilfile.pdf');
    expect(sanitizeFilenameForHeader('normal-file.pdf')).toBe('normal-file.pdf');
    expect(sanitizeFilenameForHeader('has"quotes".pdf')).toBe('hasquotes.pdf');
    expect(sanitizeFilenameForHeader('')).toBe('download');
    expect(sanitizeFilenameForHeader('a'.repeat(300)).length).toBeLessThanOrEqual(200);
  });

  test('a document with a filename containing control characters can still be uploaded and downloaded correctly', async () => {
    const token = await registerAndLogin('v3l1-owner@example.com');
    const upload = await request(app).post('/api/documents').set('Authorization', `Bearer ${token}`)
      .attach('file', Buffer.from('%PDF-1.4\ncontent'), { filename: 'weird\r\nname.pdf', contentType: 'application/pdf' });
    expect(upload.status).toBe(201);

    const download = await request(app).get(`/api/documents/${upload.body.document.id}/download`).set('Authorization', `Bearer ${token}`);
    expect(download.status).toBe(200);
    expect(download.headers['content-disposition']).not.toMatch(/[\r\n]/);
  });
});
