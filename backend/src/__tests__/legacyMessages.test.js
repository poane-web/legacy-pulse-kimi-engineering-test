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

  test('a future scheduled_date message is NOT readable by the beneficiary before release', async () => {
    const future = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
    const created = await request(app)
      .post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Future letter', body: 'Not yet!', releaseType: 'scheduled_date', releaseAt: future });
    expect(created.status).toBe(201);
    const messageId = created.body.message.id;

    const attempt = await request(app).get(`/api/legacy-messages/${messageId}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(attempt.status).toBe(403);

    const inbox = await request(app).get('/api/legacy-messages/inbox').set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(inbox.body.messages.find((m) => m.id === messageId)).toBeUndefined();
  });

  test('a past-due scheduled_date message becomes readable after the release sweep runs', async () => {
    const past = new Date(Date.now() - 1000 * 60).toISOString();
    const created = await request(app)
      .post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'Overdue letter', body: 'The time has come.', releaseType: 'scheduled_date', releaseAt: past });
    const messageId = created.body.message.id;

    runReleaseSweep();

    const read = await request(app).get(`/api/legacy-messages/${messageId}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(read.status).toBe(200);
    expect(read.body.message.body).toBe('The time has come.');
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

  test('trusted_contact_confirmation messages require the configured number of confirmations', async () => {
    const contact1Token = await registerAndLogin('trusted1@example.com');
    const contact2Token = await registerAndLogin('trusted2@example.com');

    const c1 = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Trusted One', email: 'trusted1@example.com' });
    const c1Token = c1.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contact1Token}`).send({ token: c1Token });

    const c2 = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Trusted Two', email: 'trusted2@example.com' });
    const c2Token = c2.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contact2Token}`).send({ token: c2Token });

    const ownerMe = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${ownerToken}`);
    const ownerId = ownerMe.body.user.id;

    const msg = await request(app).post('/api/legacy-messages').set('Authorization', `Bearer ${ownerToken}`)
      .send({ beneficiaryId, title: 'On my passing', body: 'Take care of each other.', releaseType: 'trusted_contact_confirmation' });
    const messageId = msg.body.message.id;

    // Before any confirmations: beneficiary cannot read
    let attempt = await request(app).get(`/api/legacy-messages/${messageId}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(attempt.status).toBe(403);

    // One confirmation: still not enough (default requires 2)
    const first = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contact1Token}`);
    expect(first.status).toBe(200);
    attempt = await request(app).get(`/api/legacy-messages/${messageId}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(attempt.status).toBe(403);

    // Second confirmation: now released
    const second = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contact2Token}`);
    expect(second.status).toBe(200);
    attempt = await request(app).get(`/api/legacy-messages/${messageId}/read`).set('Authorization', `Bearer ${beneficiaryToken}`);
    expect(attempt.status).toBe(200);
  });

  test('a trusted contact cannot submit a duplicate confirmation', async () => {
    const contactToken = await registerAndLogin('dupe-trusted@example.com');
    const c = await request(app).post('/api/trusted-contacts').set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Dupe Trusted', email: 'dupe-trusted@example.com' });
    const cToken = c.body.inviteLink.split('token=')[1].split('&')[0];
    await request(app).post('/api/trusted-contacts/claim').set('Authorization', `Bearer ${contactToken}`).send({ token: cToken });

    const ownerMe = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${ownerToken}`);
    const ownerId = ownerMe.body.user.id;

    const first = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contactToken}`);
    expect(first.status).toBe(200);
    const second = await request(app).post(`/api/trusted-contacts/confirm/${ownerId}`).set('Authorization', `Bearer ${contactToken}`);
    expect(second.status).toBe(409);
  });
});
