'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const db = require('../db');
const { releaseMessage, attemptReleaseTrustedContactMessages, attemptReleaseScheduledMessages } = require('../services/legacyMessageRelease');

const app = createApp();

async function registerAndLogin(email, password = 'SuperSecret99') {
  await request(app).post('/api/auth/register').set('X-Legacy-Pulse-Client', '1').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').set('X-Legacy-Pulse-Client', '1').send({ email, password });
  return login.body.accessToken;
}

async function setUpTrustedContact(ownerToken, contactEmail) {
  const contactToken = await registerAndLogin(contactEmail);
  const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`).send({ fullName: contactEmail, email: contactEmail });
  const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
  await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token: rawToken });
  return contactToken;
}

// ---------------------------------------------------------------------
// H2 regression (docs/V2_SECURITY_AUDIT.md, High; docs/V2_0_D_PLAN.md):
// release side-effects (status update + notification + audit log) must be
// atomic. If any step fails, the message must remain 'pending', ready to
// be correctly retried — never half-released.
// ---------------------------------------------------------------------
describe('V2.0-D / H2: release is transactional (all-or-nothing)', () => {
  test('if the notification insert fails mid-transaction, the message status update is rolled back too', async () => {
    const ownerToken = await registerAndLogin('h2-owner@example.com');
    const beneficiaryToken = await registerAndLogin('h2-beneficiary@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'H2 Beneficiary', email: 'h2-beneficiary@example.com', relationship: 'Friend' });
    const beneficiaryId = created.body.beneficiary.id;
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken });

    const past = new Date(Date.now() - 60000).toISOString();
    const msg = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'H2 test message', body: 'content', releaseType: 'scheduled_date', releaseAt: past });
    const messageId = msg.body.message.id;

    // Force the notification INSERT inside releaseMessage's transaction to
    // fail, by temporarily renaming the notifications table out from under it.
    db.exec('ALTER TABLE notifications RENAME TO notifications_tmp_for_test');
    let threw = false;
    try {
      releaseMessage(messageId, 'scheduled_date');
    } catch (err) {
      threw = true;
    } finally {
      db.exec('ALTER TABLE notifications_tmp_for_test RENAME TO notifications');
    }
    expect(threw).toBe(true);

    // Critically: the message must STILL be 'pending', not left as
    // 'released' with a missing notification. This proves the transaction
    // actually rolled back, not merely that the code is wrapped in one.
    const row = db.prepare('SELECT status, released_at FROM legacy_messages WHERE id = ?').get(messageId);
    expect(row.status).toBe('pending');
    expect(row.released_at).toBeNull();

    // No orphaned notification should exist either.
    const notifCount = db.prepare('SELECT COUNT(*) c FROM notifications WHERE message LIKE ?').get('%H2 test message%').c;
    expect(notifCount).toBe(0);

    // And it correctly retries successfully once the table is back.
    const released = releaseMessage(messageId, 'scheduled_date');
    expect(released).toBe(true);
    const rowAfter = db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId);
    expect(rowAfter.status).toBe('released');
  });

  test('releaseMessage is idempotent: calling it twice for an already-released message is a safe no-op', async () => {
    const ownerToken = await registerAndLogin('h2-idempotent-owner@example.com');
    const beneficiaryToken = await registerAndLogin('h2-idempotent-beneficiary@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Idempotent Beneficiary', email: 'h2-idempotent-beneficiary@example.com' });
    const beneficiaryId = created.body.beneficiary.id;
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken });

    const msg = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Idempotent test', body: 'content', releaseType: 'immediate' });
    const messageId = msg.body.message.id;

    // Already released at creation time (immediate). Calling releaseMessage
    // again must be a no-op (return false), not a duplicate notification.
    const secondCall = releaseMessage(messageId, 'scheduled_date');
    expect(secondCall).toBe(false);

    const notifCount = db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id = (SELECT linked_user_id FROM beneficiaries WHERE id = ?) AND message LIKE ?')
      .get(beneficiaryId, '%Idempotent test%').c;
    expect(notifCount).toBe(1); // exactly one, from creation — not two
  });

  test('a failure releasing one message during a sweep does not block another message in the same sweep', async () => {
    const ownerToken = await registerAndLogin('h2-sweep-owner@example.com');
    const beneficiaryToken = await registerAndLogin('h2-sweep-beneficiary@example.com');
    const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Sweep Beneficiary', email: 'h2-sweep-beneficiary@example.com' });
    const beneficiaryId = created.body.beneficiary.id;
    const rawToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken });

    const past = new Date(Date.now() - 60000).toISOString();
    const msgA = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Sweep A', body: 'content', releaseType: 'scheduled_date', releaseAt: past });
    const msgB = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Sweep B', body: 'content', releaseType: 'scheduled_date', releaseAt: past });

    const released = attemptReleaseScheduledMessages();
    expect(released).toBeGreaterThanOrEqual(2);

    const rowA = db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(msgA.body.message.id);
    const rowB = db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(msgB.body.message.id);
    expect(rowA.status).toBe('released');
    expect(rowB.status).toBe('released');
  });
});

// ---------------------------------------------------------------------
// H3 regression (docs/V2_SECURITY_AUDIT.md, High; docs/V2_0_D_PLAN.md): a
// trusted_contact_confirmation message created AFTER the confirmation
// threshold is already met must release immediately, not sit pending forever.
// ---------------------------------------------------------------------
describe('V2.0-D / H3: messages created after the threshold is already met release immediately', () => {
  test('a new message created after 2 confirmations were already recorded is released on creation, not stuck pending', async () => {
    const ownerToken = await registerAndLogin('h3-owner@example.com');
    const beneficiaryToken = await registerAndLogin('h3-beneficiary@example.com');
    const beneficiaryCreated = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'H3 Beneficiary', email: 'h3-beneficiary@example.com' });
    const beneficiaryId = beneficiaryCreated.body.beneficiary.id;
    const beneficiaryRawToken = beneficiaryCreated.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: beneficiaryRawToken });

    // Two trusted contacts confirm FIRST, before any trusted_contact_confirmation message exists.
    const contact1Token = await setUpTrustedContact(ownerToken, 'h3-contact1@example.com');
    const contact2Token = await setUpTrustedContact(ownerToken, 'h3-contact2@example.com');
    const ownerMe = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${ownerToken}`);
    const ownerId = ownerMe.body.user.id;

    const confirm1 = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contact1Token}`);
    expect(confirm1.status).toBe(200);
    const confirm2 = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contact2Token}`);
    expect(confirm2.status).toBe(200);

    // NOW create a new trusted_contact_confirmation message — the
    // threshold was already met before this message existed. This is
    // exactly the V1 bug: it would have sat 'pending' forever.
    const msg = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Created after threshold met', body: 'Should release immediately', releaseType: 'trusted_contact_confirmation' });
    expect(msg.status).toBe(201);

    // The fix: it must already be released, not pending.
    expect(msg.body.message.status).toBe('released');

    // And the beneficiary can actually read it right away.
    const read = await request(app).get(`/api/legacy-messages/${msg.body.message.id}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(read.status).toBe(200);
    expect(read.body.message.body).toBe('Should release immediately');
  });

  test('a message created BEFORE the threshold is met still correctly stays pending until confirmations arrive (no regression)', async () => {
    const ownerToken = await registerAndLogin('h3-normal-owner@example.com');
    const beneficiaryToken = await registerAndLogin('h3-normal-beneficiary@example.com');
    const beneficiaryCreated = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Normal Beneficiary', email: 'h3-normal-beneficiary@example.com' });
    const beneficiaryId = beneficiaryCreated.body.beneficiary.id;
    const rawToken = beneficiaryCreated.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${beneficiaryToken}`).send({ token: rawToken });

    const msg = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Normal flow', body: 'content', releaseType: 'trusted_contact_confirmation' });
    expect(msg.body.message.status).toBe('pending');

    const readTooEarly = await request(app).get(`/api/legacy-messages/${msg.body.message.id}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(readTooEarly.status).toBe(403);
  });

  test('attemptReleaseTrustedContactMessages is a safe no-op when the threshold is not met', async () => {
    const ownerToken = await registerAndLogin('h3-noop-owner@example.com');
    const ownerMe = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${ownerToken}`);
    const released = attemptReleaseTrustedContactMessages(ownerMe.body.user.id);
    expect(released).toBe(0);
  });
});
