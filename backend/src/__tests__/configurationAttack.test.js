'use strict';

/**
 * Configuration-race attacks for scheduled/milestone releases.
 *
 * These tests target the invariant that a release is one coherent snapshot:
 * configuration version + content + release time + recipient identity.
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

async function registerAndLogin(email) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  expect(login.status).toBe(200);
  return login.body.accessToken;
}

async function createBeneficiary(ownerToken, beneficiaryEmail) {
  const beneficiaryToken = await registerAndLogin(beneficiaryEmail);
  const created = await request(app)
    .post('/api/beneficiaries')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: 'Milestone Child', email: beneficiaryEmail, relationship: 'Child' });
  expect(created.status).toBe(201);
  const rawToken = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  const claimed = await request(app)
    .post('/api/beneficiaries/claim')
    .set('Authorization', `Bearer ${beneficiaryToken}`)
    .send({ token: rawToken });
  expect(claimed.status).toBe(200);
  return { id: created.body.beneficiary.id, token: beneficiaryToken };
}

async function createDueMessage(ownerToken, beneficiaryId) {
  const created = await request(app)
    .post('/api/legacy-messages')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      beneficiaryId,
      title: '18th Birthday Message',
      body: 'Happy 18th birthday — this is the original milestone payload.',
      releaseType: 'scheduled_date',
      releaseAt: new Date(Date.now() - 5000).toISOString(),
    });
  expect(created.status).toBe(201);
  return created.body.message.id;
}

describe('V2 configuration-race adversarial audit', () => {
  test('ATTACK BLOCKED: notification uses the configuration that actually won the release claim', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('config-notification-owner'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('config-notification-child'));
    const messageId = await createDueMessage(ownerToken, beneficiary.id);

    // Simulate an owner edit after the scheduler's conceptual discovery point.
    // The persisted version changes, so a stale release candidate is no longer
    // authorized to claim the row. The eventual scheduler run must use the
    // latest title, never the stale discovery title.
    const before = db.prepare('SELECT config_version, title FROM legacy_messages WHERE id = ?').get(messageId);
    db.prepare("UPDATE legacy_messages SET title = ?, config_version = config_version + 1 WHERE id = ? AND status = 'pending'")
      .run('18th Birthday — FINAL VERSION', messageId);
    const after = db.prepare('SELECT config_version, title FROM legacy_messages WHERE id = ?').get(messageId);
    expect(after.config_version).toBe(before.config_version + 1);

    expect(runReleaseSweep()).toBe(1);

    const notification = db.prepare(
      "SELECT message FROM notifications WHERE type = 'message_released' AND user_id = (SELECT linked_user_id FROM beneficiaries WHERE id = (SELECT beneficiary_id FROM legacy_messages WHERE id = ?))"
    ).get(messageId);
    expect(notification.message).toContain('18th Birthday — FINAL VERSION');
    expect(notification.message).not.toContain('18th Birthday Message" has been released');

    const released = db.prepare('SELECT status, title, config_version FROM legacy_messages WHERE id = ?').get(messageId);
    expect(released).toEqual(expect.objectContaining({ status: 'released', title: '18th Birthday — FINAL VERSION', config_version: after.config_version }));
  });

  test('ATTACK BLOCKED: stale scheduler claim cannot release after configuration version changes', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('config-stale-owner'));
    const beneficiary = await createBeneficiary(ownerToken, uniqueEmail('config-stale-child'));
    const messageId = await createDueMessage(ownerToken, beneficiary.id);

    const candidate = db.prepare('SELECT id, config_version FROM legacy_messages WHERE id = ?').get(messageId);
    db.prepare("UPDATE legacy_messages SET release_at = ?, config_version = config_version + 1 WHERE id = ? AND status = 'pending'")
      .run(new Date(Date.now() + 86_400_000).toISOString(), messageId);

    const staleClaim = db.prepare(
      "UPDATE legacy_messages SET status = 'released', released_at = ?, released_recipient_user_id = (SELECT linked_user_id FROM beneficiaries WHERE beneficiaries.id = legacy_messages.beneficiary_id) WHERE id = ? AND status = 'pending' AND release_type = 'scheduled_date' AND release_at <= ? AND config_version = ?"
    ).run(new Date().toISOString(), candidate.id, new Date().toISOString(), candidate.config_version);

    expect(staleClaim.changes).toBe(0);
    expect(db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId).status).toBe('pending');
  });

  test('ATTACK BLOCKED: changing beneficiary identity after release cannot redirect an already-released message', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('recipient-snapshot-owner'));
    const originalRecipientEmail = uniqueEmail('recipient-original');
    const original = await createBeneficiary(ownerToken, originalRecipientEmail);
    const attackerEmail = uniqueEmail('recipient-attacker');
    const attackerToken = await registerAndLogin(attackerEmail);
    const attacker = db.prepare('SELECT id FROM users WHERE email = ?').get(attackerEmail);

    const messageId = await createDueMessage(ownerToken, original.id);
    expect(runReleaseSweep()).toBe(1);

    const released = db.prepare('SELECT released_recipient_user_id FROM legacy_messages WHERE id = ?').get(messageId);
    const originalUser = db.prepare('SELECT id FROM users WHERE email = ?').get(originalRecipientEmail);
    expect(released.released_recipient_user_id).toBe(originalUser.id);

    // Simulate a future relationship/identity-management operation changing
    // the beneficiary's current linked account after release.
    db.prepare('UPDATE beneficiaries SET linked_user_id = ? WHERE id = ?').run(attacker.id, original.id);

    const originalRead = await request(app)
      .get(`/api/legacy-messages/${messageId}/read`)
      .set('Authorization', `Bearer ${original.token}`);
    expect(originalRead.status).toBe(200);

    const attackerRead = await request(app)
      .get(`/api/legacy-messages/${messageId}/read`)
      .set('Authorization', `Bearer ${attackerToken}`);
    expect(attackerRead.status).toBe(403);

    const inbox = await request(app)
      .get('/api/legacy-messages/inbox')
      .set('Authorization', `Bearer ${attackerToken}`);
    expect(inbox.status).toBe(200);
    expect(inbox.body.messages.some((m) => m.id === messageId)).toBe(false);
  });

  test('ATTACK BLOCKED: recipient identity changed before release is snapshotted atomically at release time', async () => {
    const ownerToken = await registerAndLogin(uniqueEmail('recipient-before-release-owner'));
    const original = await createBeneficiary(ownerToken, uniqueEmail('recipient-before-release-original'));
    const newRecipientEmail = uniqueEmail('recipient-before-release-new');
    const newRecipientToken = await registerAndLogin(newRecipientEmail);
    const newRecipient = db.prepare('SELECT id FROM users WHERE email = ?').get(newRecipientEmail);

    const messageId = await createDueMessage(ownerToken, original.id);
    db.prepare('UPDATE beneficiaries SET linked_user_id = ?, invite_status = \'claimed\' WHERE id = ?').run(newRecipient.id, original.id);

    expect(runReleaseSweep()).toBe(1);
    const released = db.prepare('SELECT released_recipient_user_id FROM legacy_messages WHERE id = ?').get(messageId);
    expect(released.released_recipient_user_id).toBe(newRecipient.id);

    const newRead = await request(app)
      .get(`/api/legacy-messages/${messageId}/read`)
      .set('Authorization', `Bearer ${newRecipientToken}`);
    expect(newRead.status).toBe(200);
  });
});
