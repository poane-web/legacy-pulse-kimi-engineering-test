'use strict';

// V6 attack-first suite.
// These tests deliberately target the boundary between a committed release and
// external delivery. They are expected to expose missing guarantees before any
// remediation is attempted.
require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const { runReleaseSweep } = require('../services/releaseScheduler');
const { db } = require('./testSetup');

const app = createApp();

async function registerAndLogin(email) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  return login.body.accessToken;
}

async function createScheduledMessage(ownerToken, beneficiaryId, title) {
  const past = new Date(Date.now() - 60_000).toISOString();
  const response = await request(app)
    .post('/api/legacy-messages')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      beneficiaryId,
      title,
      body: 'V6 outbox attack payload',
      releaseType: 'scheduled_date',
      releaseAt: past,
    });
  expect(response.status).toBe(201);
  return response.body.message.id;
}

describe('V6 outbox failure attacks', () => {
  let ownerToken;
  let beneficiaryId;

  beforeAll(async () => {
    ownerToken = await registerAndLogin('v6-outbox-owner@example.com');
    const beneficiaryToken = await registerAndLogin('v6-outbox-beneficiary@example.com');

    const created = await request(app)
      .post('/api/beneficiaries')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        fullName: 'V6 Outbox Beneficiary',
        email: 'v6-outbox-beneficiary@example.com',
        relationship: 'Child',
      });
    beneficiaryId = created.body.beneficiary.id;

    const inviteToken = created.body.inviteLink.split('token=')[1].split('&')[0];
    const claim = await request(app)
      .post('/api/beneficiaries/claim')
      .set('Authorization', `Bearer ${beneficiaryToken}`)
      .send({ token: inviteToken });
    expect(claim.status).toBe(200);
  });

  test('ATTACK: a committed release must have a durable outbox event', () => {
    // A release that only creates an in-process/database notification is not
    // sufficient evidence that an external delivery instruction exists.
    // This intentionally fails until the transactional outbox is implemented.
    const outboxTable = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'outbox_events'"
    ).get();
    expect(outboxTable).toBeTruthy();
  });

  test('ATTACK: release and outbox creation must commit or roll back together', async () => {
    const messageId = await createScheduledMessage(ownerToken, beneficiaryId, 'Atomic release/outbox');

    runReleaseSweep();

    const message = db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId);
    expect(message.status).toBe('released');

    // The security invariant is stronger than "a notification row exists":
    // the release must have a durable event that an independent publisher can
    // retry after process failure.
    const event = db.prepare(
      'SELECT id, aggregate_id, idempotency_key, status FROM outbox_events WHERE aggregate_id = ?'
    ).get(String(messageId));
    expect(event).toBeTruthy();
    expect(event.idempotency_key).toBe(`legacy-message:${messageId}:released`);
    expect(event.status).toBe('pending');
  });

  test('ATTACK: duplicate publisher workers must not create duplicate delivery intents', async () => {
    const messageId = await createScheduledMessage(ownerToken, beneficiaryId, 'Duplicate publisher');
    runReleaseSweep();

    const events = db.prepare(
      'SELECT id, idempotency_key FROM outbox_events WHERE aggregate_id = ?'
    ).all(String(messageId));

    // One release -> exactly one delivery intent, regardless of how many
    // publishers subsequently race to process it.
    expect(events).toHaveLength(1);
    expect(new Set(events.map((event) => event.idempotency_key)).size).toBe(1);
  });

  test('ATTACK: release must remain recoverable after a publisher crash before acknowledgement', async () => {
    const messageId = await createScheduledMessage(ownerToken, beneficiaryId, 'Publisher crash');
    runReleaseSweep();

    const event = db.prepare(
      'SELECT status, attempts, lease_until FROM outbox_events WHERE aggregate_id = ?'
    ).get(String(messageId));

    // The release transaction must not depend on a notification provider being
    // available. A crashed publisher must leave a retryable durable event.
    expect(event).toBeTruthy();
    expect(['pending', 'retryable']).toContain(event.status);
    expect(event.attempts).toBe(0);
    expect(event.lease_until == null).toBe(true);
  });

  test('ATTACK: notification success with a lost response must be idempotently retryable', async () => {
    const messageId = await createScheduledMessage(ownerToken, beneficiaryId, 'Lost response');
    runReleaseSweep();

    const event = db.prepare(
      'SELECT idempotency_key, status FROM outbox_events WHERE aggregate_id = ?'
    ).get(String(messageId));
    expect(event).toBeTruthy();

    // External delivery cannot safely be modeled as exactly-once merely by
    // changing local status. The event must carry a stable idempotency key that
    // can be supplied on every retry after a timeout/connection loss.
    expect(event.idempotency_key).toBe(`legacy-message:${messageId}:released`);
  });
});
