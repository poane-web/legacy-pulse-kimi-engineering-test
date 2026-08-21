'use strict';

/**
 * V3 production-candidate adversarial tests.
 *
 * These are deliberately written against the business invariants, not against
 * implementation details. A failure is a security finding until the root
 * cause is fixed; do not weaken the assertion to make CI green.
 */
require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const { db } = require('./testSetup');
const { runReleaseSweep } = require('../services/releaseScheduler');

const app = createApp();
let sequence = 0;

function uniqueEmail(prefix) {
  sequence += 1;
  return `${prefix}-${process.pid}-${sequence}@example.com`;
}

async function registerAndLogin(email, password = 'SuperSecret9') {
  const registered = await request(app).post('/api/auth/register').send({
    email,
    password,
    fullName: email.split('@')[0],
  });
  expect([201, 409]).toContain(registered.status);
  const login = await request(app).post('/api/auth/login').send({ email, password });
  expect(login.status).toBe(200);
  return login.body.accessToken;
}

async function createBeneficiary(ownerToken, email) {
  const beneficiaryToken = await registerAndLogin(email);
  const created = await request(app)
    .post('/api/beneficiaries')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: 'Milestone Child', email, relationship: 'Child' });
  expect(created.status).toBe(201);
  const rawToken = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  const claimed = await request(app)
    .post('/api/beneficiaries/claim')
    .set('Authorization', `Bearer ${beneficiaryToken}`)
    .send({ token: rawToken });
  expect(claimed.status).toBe(200);
  return { id: created.body.beneficiary.id, token: beneficiaryToken, email };
}

async function createTrustedContact(ownerToken, email, name) {
  const contactToken = await registerAndLogin(email);
  const created = await request(app)
    .post('/api/trusted-contacts')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: name, email });
  expect(created.status).toBe(201);
  const rawToken = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  const claimed = await request(app)
    .post('/api/trusted-contacts/claim')
    .set('Authorization', `Bearer ${contactToken}`)
    .send({ token: rawToken });
  expect(claimed.status).toBe(200);
  return { id: created.body.trustedContact.id, token: contactToken };
}

async function createConfirmationMessage(ownerToken, beneficiaryId) {
  const created = await request(app)
    .post('/api/legacy-messages')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      beneficiaryId,
      title: 'V3 confirmation target',
      body: 'Sensitive milestone payload',
      releaseType: 'trusted_contact_confirmation',
    });
  expect(created.status).toBe(201);
  return created.body.message.id;
}

async function createScheduledMessage(ownerToken, beneficiaryId, releaseAt) {
  const created = await request(app)
    .post('/api/legacy-messages')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      beneficiaryId,
      title: 'V3 scheduled target',
      body: 'Sensitive scheduled payload',
      releaseType: 'scheduled_date',
      releaseAt,
    });
  expect(created.status).toBe(201);
  return created.body.message.id;
}

describe('V3 production-candidate adversarial audit', () => {
  test('ATTACK BLOCKED: final trusted-contact confirmation snapshots the recipient atomically', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('v3-owner-recipient'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('v3-child'));
    const contactA = await createTrustedContact(ownerToken, uniqueEmail('v3-tc-a'), 'Contact A');
    const contactB = await createTrustedContact(ownerToken, uniqueEmail('v3-tc-b'), 'Contact B');
    const messageId = await createConfirmationMessage(ownerToken, beneficiary.id);

    const first = await request(app)
      .post(`/api/trusted-contacts/confirm/${messageId}`)
      .set('Authorization', `Bearer ${contactA.token}`);
    expect(first.status).toBe(200);
    expect(first.body.released).toBe(false);

    const second = await request(app)
      .post(`/api/trusted-contacts/confirm/${messageId}`)
      .set('Authorization', `Bearer ${contactB.token}`);
    expect(second.status).toBe(200);
    expect(second.body.released).toBe(true);

    const row = db.prepare('SELECT status, released_recipient_user_id FROM legacy_messages WHERE id = ?').get(messageId);
    const child = db.prepare('SELECT linked_user_id FROM beneficiaries WHERE id = ?').get(beneficiary.id);

    // The identity authorized at release must be durable and non-null.
    expect(row.status).toBe('released');
    expect(row.released_recipient_user_id).toBe(child.linked_user_id);

    const inbox = await request(app)
      .get('/api/legacy-messages/inbox')
      .set('Authorization', `Bearer ${beneficiary.token}`);
    expect(inbox.status).toBe(200);
    expect(inbox.body.messages.some((m) => m.id === messageId)).toBe(true);

    const read = await request(app)
      .get(`/api/legacy-messages/${messageId}/read`)
      .set('Authorization', `Bearer ${beneficiary.token}`);
    expect(read.status).toBe(200);
    expect(read.body.message.body).toBe('Sensitive milestone payload');
  });

  test('ATTACK BLOCKED: a confirmation cannot release to a beneficiary identity changed between confirmations', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('v3-owner-identity'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('v3-child-original'));
    const replacement = await registerAndLogin(uniqueEmail('v3-child-replacement'));
    const contactA = await createTrustedContact(ownerToken, uniqueEmail('v3-id-tc-a'), 'Contact A');
    const contactB = await createTrustedContact(ownerToken, uniqueEmail('v3-id-tc-b'), 'Contact B');
    const messageId = await createConfirmationMessage(ownerToken, beneficiary.id);

    const first = await request(app)
      .post(`/api/trusted-contacts/confirm/${messageId}`)
      .set('Authorization', `Bearer ${contactA.token}`);
    expect(first.status).toBe(200);

    // Simulate the strongest identity-mutation race at the persistence layer.
    // The release must bind to a stable recipient identity rather than reading
    // beneficiary.linked_user_id after the final confirmation.
    const original = db.prepare('SELECT linked_user_id FROM beneficiaries WHERE id = ?').get(beneficiary.id).linked_user_id;
    const replacementUser = db.prepare('SELECT id FROM users WHERE email = ?').get(replacement.body.user.email).id;
    expect(replacementUser).not.toBe(original);
    db.prepare('UPDATE beneficiaries SET linked_user_id = ? WHERE id = ?').run(replacementUser, beneficiary.id);

    const second = await request(app)
      .post(`/api/trusted-contacts/confirm/${messageId}`)
      .set('Authorization', `Bearer ${contactB.token}`);
    expect(second.status).toBe(200);
    expect(second.body.released).toBe(false);

    // The safest outcome is to reject the release because the recipient
    // identity changed after authorization began. A mutable relationship must
    // never silently redirect a release to a different person.
    const row = db.prepare('SELECT status, released_recipient_user_id FROM legacy_messages WHERE id = ?').get(messageId);
    expect(row.status).toBe('pending');
    expect(row.released_recipient_user_id).toBeNull();
  });

  test('ATTACK BLOCKED: duplicate scheduler execution cannot create duplicate recipient notifications', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('v3-owner-scheduler'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('v3-scheduler-child'));
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id, new Date(Date.now() - 5000).toISOString());

    const results = Array.from({ length: 20 }, () => runReleaseSweep());
    expect(results.filter(Boolean)).toHaveLength(1);

    const row = db.prepare('SELECT status, released_recipient_user_id FROM legacy_messages WHERE id = ?').get(messageId);
    expect(row.status).toBe('released');
    expect(row.released_recipient_user_id).toBeTruthy();

    const notifications = db.prepare(
      "SELECT COUNT(*) AS c FROM notifications WHERE type = 'message_released' AND user_id = ?"
    ).get(row.released_recipient_user_id);
    expect(notifications.c).toBe(1);
  });

  test('ATTACK BLOCKED: disabled owner JWT cannot mutate release configuration', async () => {
    const ownerEmail = uniqueEmail('v3-owner-disabled');
    const ownerToken = await registerAndLogin(ownerEmail);
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('v3-disabled-child'));
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id, new Date(Date.now() + 3600000).toISOString());
    const owner = db.prepare('SELECT id FROM users WHERE email = ?').get(ownerEmail);
    db.prepare("UPDATE users SET status = 'disabled' WHERE id = ?").run(owner.id);

    const edited = await request(app)
      .put(`/api/legacy-messages/${messageId}`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ title: 'ATTACKED' });
    expect(edited.status).toBe(401);
    expect(db.prepare('SELECT title FROM legacy_messages WHERE id = ?').get(messageId).title).toBe('V3 scheduled target');
  });

  test('ATTACK BLOCKED: release eligibility is not retroactively widened by a configuration edit race', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('v3-owner-race'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('v3-race-child'));
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id, new Date(Date.now() - 5000).toISOString());

    const before = db.prepare('SELECT config_version FROM legacy_messages WHERE id = ?').get(messageId).config_version;
    db.prepare("UPDATE legacy_messages SET release_at = ?, config_version = config_version + 1 WHERE id = ?").run(new Date(Date.now() + 3600000).toISOString(), messageId);
    expect(runReleaseSweep()).toBe(0);
    const after = db.prepare('SELECT status, config_version FROM legacy_messages WHERE id = ?').get(messageId);
    expect(after.status).toBe('pending');
    expect(after.config_version).toBe(before + 1);
  });
});
