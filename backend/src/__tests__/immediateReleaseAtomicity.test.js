'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');
const { db } = require('./testSetup');

const app = createApp();

async function registerAndLogin(email) {
  const password = 'SuperSecret9';
  await request(app).post('/api/auth/register').send({ email, password, fullName: email.split('@')[0] });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  return login.body.accessToken;
}

async function createBeneficiary(ownerToken, email, name) {
  const beneficiaryToken = await registerAndLogin(email);
  const created = await request(app).post('/api/beneficiaries')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ fullName: name, email, relationship: 'Child' });
  const token = created.body.inviteLink.split('token=')[1].split('&')[0];
  await request(app).post('/api/beneficiaries/claim')
    .set('Authorization', `Bearer ${beneficiaryToken}`)
    .send({ token });
  return created.body.beneficiary.id;
}

describe('Immediate release atomicity adversarial tests', () => {
  test('notification failure cannot leave an immediate message released without its notification', async () => {
    const ownerToken = await registerAndLogin('atomic-owner@example.com');
    const beneficiaryId = await createBeneficiary(ownerToken, 'atomic-beneficiary@example.com', 'Atomic Child');

    db.exec(`
      CREATE TRIGGER test_fail_notification
      BEFORE INSERT ON notifications
      BEGIN
        SELECT RAISE(ABORT, 'forced notification failure');
      END;
    `);

    try {
      const response = await request(app)
        .post('/api/legacy-messages')
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({
          beneficiaryId,
          title: 'Atomic immediate release',
          body: 'Must roll back',
          releaseType: 'immediate',
        });

      expect(response.status).toBeGreaterThanOrEqual(500);
      const message = db.prepare("SELECT id, status, released_recipient_user_id FROM legacy_messages WHERE title = ?").get('Atomic immediate release');
      expect(message).toBeUndefined();

      const notifications = db.prepare("SELECT COUNT(*) AS count FROM notifications WHERE type = 'message_released'").get().count;
      expect(notifications).toBe(0);
    } finally {
      db.exec('DROP TRIGGER IF EXISTS test_fail_notification');
    }
  });
});
