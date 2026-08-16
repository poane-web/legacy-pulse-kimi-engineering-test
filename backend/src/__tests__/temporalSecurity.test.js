'use strict';

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

async function createBeneficiary(ownerToken, email, name) {
  const beneficiary = await registerAndLogin(email);
  const created = await request(app).post('/api/beneficiaries')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: name, email, relationship: 'Child' });
  const token = created.body.inviteLink.split('token=')[1].split('&')[0];
  await request(app).post('/api/beneficiaries/claim')
    .set('Authorization', `Bearer ${beneficiary}`)
    .send({ token });
  return { id: created.body.beneficiary.id, token: beneficiary };
}

describe('Temporal business-logic adversarial tests', () => {
  let ownerToken;
  let beneficiaryId;

  beforeAll(async () => {
    ownerToken = await registerAndLogin('temporal-owner@example.com');
    const beneficiary = await createBeneficiary(ownerToken, 'temporal-beneficiary@example.com', 'Temporal Child');
    beneficiaryId = beneficiary.id;
  });

  test('release timestamps are canonicalized to UTC so offset representations cannot reorder deadlines', async () => {
    const localOffset = '2030-01-01T12:00:00+02:00';
    const created = await request(app).post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'UTC test', body: 'Time-safe', releaseType: 'scheduled_date', releaseAt: localOffset });

    expect(created.status).toBe(201);
    expect(created.body.message.releaseAt).toBe('2030-01-01T10:00:00.000Z');
  });

  test('a released message cannot be edited through a stale pending session', async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const created = await request(app).post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Race target', body: 'Original', releaseType: 'scheduled_date', releaseAt: past });
    const id = created.body.message.id;

    // Simulate another worker winning the release between the owner's
    // authorization read and the subsequent UPDATE.
    runReleaseSweep();

    const edit = await request(app).put(`/api/legacy-messages/${id}`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ title: 'Attacker overwrite' });

    expect(edit.status).toBe(400);
    const row = db.prepare('SELECT status, title FROM legacy_messages WHERE id = ?').get(id);
    expect(row.status).toBe('released');
    expect(row.title).toBe('Race target');
  });

  test('a beneficiary cannot be deleted while a released or pending legacy message references it', async () => {
    const future = new Date(Date.now() + 86_400_000).toISOString();
    const created = await request(app).post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Retention test', body: 'Must survive relationship changes', releaseType: 'scheduled_date', releaseAt: future });

    const deletion = await request(app).delete(`/api/beneficiaries/${beneficiaryId}`)
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(deletion.status).toBe(409);
    expect(db.prepare('SELECT id FROM legacy_messages WHERE id = ?').get(created.body.message.id)).toBeTruthy();
  });

  test('owner-wide confirmations cannot satisfy a new message release', () => {
    const message = db.prepare(
      "SELECT id FROM legacy_messages WHERE owner_id = (SELECT id FROM users WHERE email = ?) AND release_type = 'trusted_contact_confirmation' AND status = 'pending' ORDER BY id DESC LIMIT 1"
    ).get('temporal-owner@example.com');
    if (!message) return;

    // Legacy V2 data may contain owner-wide confirmation rows with NULL
    // legacy_message_id. They must never count toward this message.
    db.prepare('INSERT INTO release_confirmations (owner_id, trusted_contact_id) SELECT owner_id, id FROM trusted_contacts WHERE owner_id = (SELECT owner_id FROM legacy_messages WHERE id = ?) LIMIT 1').run(message.id);
    const count = db.prepare('SELECT COUNT(*) AS c FROM release_confirmations WHERE legacy_message_id = ?').get(message.id).c;
    expect(count).toBe(0);
  });
});
