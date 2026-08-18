'use strict';

/**
 * Adversarial audit tests. These intentionally demonstrate exploitable
 * temporal/authority behavior; they are not production fixes.
 */
require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const { db } = require('./testSetup');

const app = createApp();

async function registerAndLogin(email) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  expect(login.status).toBe(200);
  return login.body.accessToken;
}

async function createOwnTrustedContact(ownerToken, ownerEmail, name) {
  const created = await request(app)
    .post('/api/trusted-contacts')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: name, email: ownerEmail });
  expect(created.status).toBe(201);

  const rawToken = new URL(`http://localhost${created.body.inviteLink}`).searchParams.get('token');
  const claimed = await request(app)
    .post('/api/trusted-contacts/claim')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ token: rawToken });
  expect(claimed.status).toBe(200);

  return created.body.trustedContact.id;
}

describe('V2 temporal adversarial audit', () => {
  test('ATTACK PROOF: owner can manufacture two distinct trusted-contact identities and release their own passing message', async () => {
    const ownerEmail = 'attack-owner-self-tc@example.com';
    const ownerToken = await registerAndLogin(ownerEmail);

    // No production endpoint currently rejects owner-as-trusted-contact.
    const contactA = await createOwnTrustedContact(ownerToken, ownerEmail, 'Owner Contact A');
    const contactB = await createOwnTrustedContact(ownerToken, ownerEmail, 'Owner Contact B');

    expect(contactA).not.toBe(contactB);
    expect(
      db.prepare('SELECT COUNT(*) AS c FROM trusted_contacts WHERE owner_id = (SELECT id FROM users WHERE email = ?) AND linked_user_id = (SELECT id FROM users WHERE email = ?) AND status = ?').get(ownerEmail, ownerEmail, 'active').c
    ).toBe(2);

    // Create a beneficiary for the release target.
    const beneficiaryEmail = 'attack-beneficiary@example.com';
    const beneficiaryToken = await registerAndLogin(beneficiaryEmail);
    const beneficiaryCreated = await request(app)
      .post('/api/beneficiaries')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ fullName: 'Attack Beneficiary', email: beneficiaryEmail, relationship: 'Child' });
    const beneficiaryInvite = new URL(`http://localhost${beneficiaryCreated.body.inviteLink}`).searchParams.get('token');
    await request(app)
      .post('/api/beneficiaries/claim')
      .set('Authorization', `Bearer ${beneficiaryToken}`)
      .send({ token: beneficiaryInvite });

    const created = await request(app)
      .post('/api/legacy-messages')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        beneficiaryId: beneficiaryCreated.body.beneficiary.id,
        title: 'Self-authorized release',
        body: 'Should not release through owner-controlled confirmations',
        releaseType: 'trusted_contact_confirmation',
      });
    expect(created.status).toBe(201);
    const messageId = created.body.message.id;

    const first = await request(app)
      .post(`/api/trusted-contacts/confirm/${messageId}`)
      .set('Authorization', `Bearer ${ownerToken}`);
    const second = await request(app)
      .post(`/api/trusted-contacts/confirm/${messageId}`)
      .set('Authorization', `Bearer ${ownerToken}`);

    // Current implementation accepts both confirmations because it keys
    // confirmation uniqueness by trusted_contact_id, while both identities
    // resolve to the owner. This is the vulnerability being demonstrated.
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(second.body.released).toBe(true);

    const row = db.prepare('SELECT status FROM legacy_messages WHERE id = ?').get(messageId);
    expect(row.status).toBe('released');
  });
});
