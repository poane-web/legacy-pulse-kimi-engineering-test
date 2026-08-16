'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const { runReleaseSweep } = require('../services/releaseScheduler');

const app = createApp();

async function registerAndLogin(email) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  return login.body.accessToken;
}

describe('Legacy message release conditions', () => {
  let ownerToken;
  let beneficiaryToken;
  let beneficiaryId;

  beforeAll(async () => {
    ownerToken = await registerAndLogin('legacy-owner@example.com');
    beneficiaryToken = await registerAndLogin('legacy-beneficiary@example.com');

    const created = await request(app)
      .post('/api/beneficiaries')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Beneficiary Person', email: 'legacy-beneficiary@example.com', relationship: 'Child' });
    beneficiaryId = created.body.beneficiary.id;
    const inviteToken = created.body.inviteLink.split('token=')[1].split('&')[0];

    const claim = await request(app)
      .post('/api/beneficiaries/claim')
      .set('Authorization', `Bearer ${beneficiaryToken}`)
      .send({ token: inviteToken });
    expect(claim.status).toBe(200);
  });

  test('a future scheduled message is not readable before release', async () => {
    const future = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
    const created = await request(app)
      .post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Future letter', body: 'Not yet!', releaseType: 'scheduled_date', releaseAt: future });
    expect(created.status).toBe(201);
    const messageId = created.body.message.id;

    const attempt = await request(app).get(`/api/legacy-messages/${messageId}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(attempt.status).toBe(403);
  });

  test('a past-due scheduled message becomes readable after the release sweep', async () => {
    const past = new Date(Date.now() - 1000 * 60).toISOString();
    const created = await request(app)
      .post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Overdue letter', body: 'The time has come.', releaseType: 'scheduled_date', releaseAt: past });
    const messageId = created.body.message.id;

    expect(runReleaseSweep()).toBeGreaterThanOrEqual(1);
    const read = await request(app).get(`/api/legacy-messages/${messageId}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(read.status).toBe(200);
    expect(read.body.message.body).toBe('The time has come.');
  });

  test('a second sweep cannot release the same scheduled message twice', async () => {
    const past = new Date(Date.now() - 1000 * 60).toISOString();
    const created = await request(app)
      .post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Exactly once', body: 'One release.', releaseType: 'scheduled_date', releaseAt: past });
    const messageId = created.body.message.id;

    expect(runReleaseSweep()).toBeGreaterThanOrEqual(1);
    expect(runReleaseSweep()).toBe(0);
    const row = require('./testSetup').db.prepare('SELECT status, released_at FROM legacy_messages WHERE id = ?').get(messageId);
    expect(row.status).toBe('released');
    expect(row.released_at).toBeTruthy();
  });

  test('a different beneficiary account cannot read a message addressed to someone else', async () => {
    const otherToken = await registerAndLogin('other-beneficiary@example.com');
    const past = new Date(Date.now() - 1000 * 60).toISOString();
    const created = await request(app)
      .post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Private letter', body: 'For one person only.', releaseType: 'scheduled_date', releaseAt: past });
    runReleaseSweep();

    const attempt = await request(app).get(`/api/legacy-messages/${created.body.message.id}/read`).set('Authorization', `Bearer ${otherToken}`);
    expect(attempt.status).toBe(403);
  });

  test('trusted-contact confirmations are scoped to one message', async () => {
    const contact1Token = await registerAndLogin('scoped-trusted1@example.com');
    const contact2Token = await registerAndLogin('scoped-trusted2@example.com');

    const c1 = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Scoped Trusted One', email: 'scoped-trusted1@example.com' });
    const c1Token = c1.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contact1Token}`).send({ token: c1Token });

    const c2 = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Scoped Trusted Two', email: 'scoped-trusted2@example.com' });
    const c2Token = c2.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contact2Token}`).send({ token: c2Token });

    const msgA = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Message A', body: 'A', releaseType: 'trusted_contact_confirmation' });
    const msgB = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Message B', body: 'B', releaseType: 'trusted_contact_confirmation' });

    const a1 = await request(app).post(`/api/trusted-contacts/confirm/${msgA.body.message.id}`).set('Authorization', `Bearer ${contact1Token}`);
    expect(a1.status).toBe(200);
    expect(a1.body.released).toBe(false);

    const a2 = await request(app).post(`/api/trusted-contacts/confirm/${msgA.body.message.id}`).set('Authorization', `Bearer ${contact2Token}`);
    expect(a2.status).toBe(200);
    expect(a2.body.released).toBe(true);

    const bRead = await request(app).get(`/api/legacy-messages/${msgB.body.message.id}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(bRead.status).toBe(403);
  });

  test('the same trusted contact cannot confirm the same message twice', async () => {
    const contactToken = await registerAndLogin('scoped-dupe@example.com');
    const c = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Scoped Dupe', email: 'scoped-dupe@example.com' });
    const cToken = c.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token: cToken });

    const msg = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Duplicate test', body: 'D', releaseType: 'trusted_contact_confirmation' });

    const first = await request(app).post(`/api/trusted-contacts/confirm/${msg.body.message.id}`).set('Authorization', `Bearer ${contactToken}`);
    expect(first.status).toBe(200);
    const second = await request(app).post(`/api/trusted-contacts/confirm/${msg.body.message.id}`).set('Authorization', `Bearer ${contactToken}`);
    expect(second.status).toBe(409);
  });
});
