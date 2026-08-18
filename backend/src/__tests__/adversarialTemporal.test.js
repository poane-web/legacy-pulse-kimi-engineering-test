'use strict';

/**
 * Adversarial temporal/authority tests.
 *
 * These tests are intentionally attacker-driven. A failing test means the
 * application violated a release invariant; it does NOT mean the test itself
 * should be weakened to make CI green.
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
  await request(app).post('/api/auth/register').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  expect(login.status).toBe(200);
  return login.body.accessToken;
}

async function createTrustedContact(ownerToken, contactEmail, name) {
  const created = await request(app)
    .post('/api/trusted-contacts')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: name, email: contactEmail });
  expect(created.status).toBe(201);
  const rawToken = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  return { id: created.body.trustedContact.id, rawToken };
}

async function claimTrustedContact(contactToken, rawToken) {
  const claimed = await request(app)
    .post('/api/trusted-contacts/claim')
    .set('Authorization', `Bearer ${contactToken}`)
    .send({ token: rawToken });
  expect(claimed.status).toBe(200);
}

async function createBeneficiary(ownerToken, beneficiaryEmail) {
  const beneficiaryToken = await registerAndLogin(beneficiaryEmail);
  const created = await request(app)
    .post('/api/beneficiaries')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: 'Test Beneficiary', email: beneficiaryEmail, relationship: 'Child' });
  expect(created.status).toBe(201);
  const rawToken = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  const claimed = await request(app)
    .post('/api/beneficiaries/claim')
    .set('Authorization', `Bearer ${beneficiaryToken}`)
    .send({ token: rawToken });
  expect(claimed.status).toBe(200);
  return { id: created.body.beneficiary.id, token: beneficiaryToken, email: beneficiaryEmail };
}

async function createScheduledMessage(ownerToken, beneficiaryId, releaseAt = new Date(Date.now() + 60_000).toISOString()) {
  const created = await request(app)
    .post('/api/legacy-messages')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ beneficiaryId, title: 'Temporal attack target', body: 'Sensitive milestone payload', releaseType: 'scheduled_date', releaseAt });
  expect(created.status).toBe(201);
  return created.body.message.id;
}

async function createConfirmationMessage(ownerToken, beneficiaryId, requiredConfirmations = 2) {
  const created = await request(app)
    .post('/api/legacy-messages')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ beneficiaryId, title: 'Confirmation target', body: 'Sensitive confirmation payload', releaseType: 'trusted_contact_confirmation' });
  expect(created.status).toBe(201);
  if (requiredConfirmations !== 2) {
    db.prepare('UPDATE legacy_messages SET required_confirmations = ? WHERE id = ?').run(requiredConfirmations, created.body.message.id);
  }
  return created.body.message.id;
}

describe('V2 temporal adversarial audit', () => {
  test('ATTACK BLOCKED: owner cannot turn two owner-linked contact rows into two confirmations', async () => {
    const ownerEmail = uniqueEmail('owner-self-tc');
    const ownerToken = await registerAndLogin(ownerEmail);
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('beneficiary'));

    const createA = await request(app)
      .post('/api/trusted-contacts')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Owner Contact A', email: ownerEmail });
    const createB = await request(app)
      .post('/api/trusted-contacts')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Owner Contact B', email: ownerEmail });
    expect(createA.status).toBe(403);
    expect(createB.status).toBe(403);

    // Defense in depth: simulate legacy rows that predate the self-contact
    // creation guard. The confirmation endpoint must reject the owner's
    // identity even when such rows already exist in storage.
    const owner = db.prepare('SELECT id FROM users WHERE email = ?').get(ownerEmail);
    const contactA = db.prepare("INSERT INTO trusted_contacts (owner_id, full_name, email, status, linked_user_id) VALUES (?, ?, ?, 'active', ?)").run(owner.id, 'Legacy Owner Contact A', ownerEmail, owner.id);
    const contactB = db.prepare("INSERT INTO trusted_contacts (owner_id, full_name, email, status, linked_user_id) VALUES (?, ?, ?, 'active', ?)").run(owner.id, 'Legacy Owner Contact B', ownerEmail, owner.id);
    expect(contactA.lastInsertRowid).not.toBe(contactB.lastInsertRowid);

    const messageId = await createConfirmationMessage(ownerToken, beneficiary.id);
    const first = await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${ownerToken}`);
    const second = await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${ownerToken}`);

    expect(first.status).toBe(403);
    expect(second.status).toBe(403);
    expect(db.prepare('SELECT COUNT(*) AS c FROM release_confirmations WHERE legacy_message_id = ?').get(messageId).c).toBe(0);
    expect(db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId).status).toBe('pending');
  });

  test('ATTACK BLOCKED: revoked trusted contact cannot contribute to final confirmation', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('owner-revoke'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('beneficiary'));
    const contactAEmail = uniqueEmail('tc-a');
    const contactBEmail = uniqueEmail('tc-b');
    const contactAToken = await registerAndLogin(contactAEmail);
    const contactBToken = await registerAndLogin(contactBEmail);
    const contactA = await createTrustedContact(ownerToken, contactAEmail, 'Contact A');
    const contactB = await createTrustedContact(ownerToken, contactBEmail, 'Contact B');
    await claimTrustedContact(contactAToken, contactA.rawToken);
    await claimTrustedContact(contactBToken, contactB.rawToken);

    const messageId = await createConfirmationMessage(ownerToken, beneficiary.id);
    const first = await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${contactAToken}`);
    expect(first.status).toBe(200);

    const revoked = await request(app).delete(`/api/trusted-contacts/${contactA.id}`).set('Authorization', `Bearer ${ownerToken}`);
    expect(revoked.status).toBe(204);

    const second = await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${contactBToken}`);
    expect(second.status).toBe(200);
    expect(second.body.released).toBe(false);
    expect(db.prepare('SELECT COUNT(*) AS c FROM release_confirmations WHERE legacy_message_id = ?').get(messageId).c).toBe(1);
    expect(db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId).status).toBe('pending');

    const replay = await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${contactAToken}`);
    expect(replay.status).toBe(403);
  });

  test('ATTACK BLOCKED: disabling an account invalidates an already-issued access JWT', async () => {
    const email = uniqueEmail('disabled-jwt');
    const token = await registerAndLogin(email);
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    db.prepare("UPDATE users SET status = 'disabled' WHERE id = ?").run(user.id);
    const response = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(response.status).toBe(401);
  });

  test('ATTACK BLOCKED: password-change timestamp invalidates a pre-change access JWT', async () => {
    const email = uniqueEmail('password-rotation');
    const token = await registerAndLogin(email);
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    db.prepare("UPDATE users SET password_changed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','+1 second') WHERE id = ?").run(user.id);
    const response = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(response.status).toBe(401);
  });

  test('ATTACK BLOCKED: beneficiary deletion cannot destroy a pending or released message', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('beneficiary-delete'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('beneficiary'));
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id);
    const deleted = await request(app).delete(`/api/beneficiaries/${beneficiary.id}`).set('Authorization', `Bearer ${ownerToken}`);
    expect(deleted.status).toBe(409);
    expect(db.prepare('SELECT id FROM legacy_messages WHERE id = ?').get(messageId)).toBeTruthy();
  });

  test('ATTACK BLOCKED: scheduled release wins cleanly over a stale owner edit', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('schedule-edit-race'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('beneficiary'));
    const releaseAt = new Date(Date.now() - 5_000).toISOString();
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id, releaseAt);
    const released = runReleaseSweep();
    expect(released).toBe(1);
    const edited = await request(app).put(`/api/legacy-messages/${messageId}`).set('Authorization', `Bearer ${ownerToken}`).send({ title: 'ATTACKED AFTER RELEASE' });
    expect(edited.status).toBe(400);
    expect(db.prepare('SELECT status, title FROM legacy_messages WHERE id = ?').get(messageId)).toEqual(expect.objectContaining({ status: 'released', title: 'Temporal attack target' }));
  });

  test('ATTACK BLOCKED: scheduler restart cannot duplicate a scheduled release or notification', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('scheduler-restart'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('beneficiary'));
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id, new Date(Date.now() - 5_000).toISOString());
    expect(runReleaseSweep()).toBe(1);
    expect(runReleaseSweep()).toBe(0);
    const row = db.prepare("SELECT COUNT(*) AS c FROM notifications WHERE type = 'message_released' AND user_id = (SELECT linked_user_id FROM beneficiaries WHERE id = (SELECT beneficiary_id FROM legacy_messages WHERE id = ?))").get(messageId);
    expect(row.c).toBe(1);
  });

  test('ATTACK REVEAL: release can commit before notification delivery succeeds', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('notification-gap'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('beneficiary'));
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id, new Date(Date.now() - 5_000).toISOString());
    db.exec("CREATE TRIGGER fail_notification_insert BEFORE INSERT ON notifications BEGIN SELECT RAISE(ABORT, 'simulated notification outage'); END;");
    expect(() => runReleaseSweep()).toThrow();
    db.exec('DROP TRIGGER fail_notification_insert');
    expect(db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId).status).toBe('released');
    expect(db.prepare("SELECT COUNT(*) AS c FROM notifications WHERE user_id = (SELECT linked_user_id FROM beneficiaries WHERE id = (SELECT beneficiary_id FROM legacy_messages WHERE id = ?)) AND type = 'message_released'").get(messageId).c).toBe(0);
    expect(runReleaseSweep()).toBe(0);
  });

  test('ATTACK BLOCKED: concurrent scheduled sweeps perform exactly one state transition', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('scheduler-concurrency'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('beneficiary'));
    const messageId = await createScheduledMessage(ownerToken, beneficiary.id, new Date(Date.now() - 5_000).toISOString());
    const results = await Promise.all(Array.from({ length: 10 }, () => Promise.resolve().then(() => runReleaseSweep())));
    expect(results.reduce((a, b) => a + b, 0)).toBe(1);
    expect(db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId).status).toBe('released');
    expect(db.prepare("SELECT COUNT(*) AS c FROM notifications WHERE user_id = (SELECT linked_user_id FROM beneficiaries WHERE id = (SELECT beneficiary_id FROM legacy_messages WHERE id = ?)) AND type = 'message_released'").get(messageId).c).toBe(1);
  });
});
