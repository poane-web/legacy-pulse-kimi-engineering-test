'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const { db } = require('./testSetup');

const app = createApp();
let sequence = 0;
const email = (p) => `${p}-${process.pid}-${++sequence}@example.com`;

async function login(e) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').send({ email: e, password, fullName: 'V3 Test User' });
  const r = await request(app).post('/api/auth/login').send({ email: e, password });
  expect(r.status).toBe(200);
  return r.body.accessToken;
}

async function beneficiary(ownerToken, e) {
  const childToken = await login(e);
  const created = await request(app).post('/api/beneficiaries').set('Authorization', `Bearer ${ownerToken}`).send({
    fullName: 'V3 Child', email: e, relationship: 'Child',
  });
  expect(created.status).toBe(201);
  const token = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  const claimed = await request(app).post('/api/beneficiaries/claim').set('Authorization', `Bearer ${childToken}`).send({ token });
  expect(claimed.status).toBe(200);
  return { id: created.body.beneficiary.id, token: childToken };
}

async function contact(ownerToken, e) {
  const contactToken = await login(e);
  const created = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`).send({ fullName: 'V3 Contact', email: e });
  expect(created.status).toBe(201);
  const token = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  const claimed = await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token });
  expect(claimed.status).toBe(200);
  return contactToken;
}

test('ATTACK BLOCKED: trusted-contact release and notification are atomic', async () => {
  const owner = await login(email('v3-atomic-owner'));
  const child = await beneficiary(owner, email('v3-atomic-child'));
  const tcA = await contact(owner, email('v3-atomic-tc-a'));
  const tcB = await contact(owner, email('v3-atomic-tc-b'));

  const created = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${owner}`).send({
    beneficiaryId: child.id,
    title: 'Atomic release',
    body: 'Atomic release payload',
    releaseType: 'trusted_contact_confirmation',
  });
  expect(created.status).toBe(201);
  const messageId = created.body.message.id;

  expect((await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${tcA}`)).status).toBe(200);

  db.exec("CREATE TRIGGER fail_v3_notification BEFORE INSERT ON notifications BEGIN SELECT RAISE(ABORT, 'simulated notification outage'); END;");
  try {
    const final = await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${tcB}`);
    expect(final.status).toBeGreaterThanOrEqual(500);
  } finally {
    db.exec('DROP TRIGGER fail_v3_notification');
  }

  const row = db.prepare('SELECT status, released_recipient_user_id FROM legacy_messages WHERE id = ?').get(messageId);
  expect(row.status).toBe('pending');
  expect(row.released_recipient_user_id).toBeNull();
  expect(db.prepare('SELECT COUNT(*) AS c FROM release_confirmations WHERE legacy_message_id = ?').get(messageId).c).toBe(1);

  const retry = await request(app).post(`/api/trusted-contacts/confirm/${messageId}`).set('Authorization', `Bearer ${tcB}`);
  expect(retry.status).toBe(200);
  expect(retry.body.released).toBe(true);
  expect(db.prepare('SELECT status, released_recipient_user_id FROM legacy_messages WHERE id = ?').get(messageId).status).toBe('released');
});
