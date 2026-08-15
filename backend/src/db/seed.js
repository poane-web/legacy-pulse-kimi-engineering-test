// Seeds demo data for local evaluation:
// - an admin account
// - an owner account ("Thandiwe Moyo") with beneficiaries, trusted
//   contacts, memories, a life-event timeline, and legacy messages in a
//   mix of states (pending / released) so every dashboard view has
//   something to show.
// - a beneficiary account already linked, so the "beneficiary inbox"
//   feature can be demoed immediately without manually claiming invites.
//
// Idempotent: running twice will fail on the UNIQUE email constraint
// rather than silently duplicating rows, which is what we want for a demo
// seed (predictable state). Delete backend/data/legacy_pulse.db to reset.
'use strict';

const bcrypt = require('bcrypt');
const db = require('./index');
const config = require('../config/env');
const { encryptField } = require('../utils/crypto');

async function seed() {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get('owner@demo.legacypulse.test');
  if (existing) {
    console.log('[seed] Demo data already present, skipping. Delete backend/data/legacy_pulse.db to reset.');
    return;
  }

  const pw = await bcrypt.hash('DemoPass123!', config.bcryptCost);

  const admin = db.prepare('INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
    .run('admin@demo.legacypulse.test', pw, 'Platform Admin', 'admin');

  const owner = db.prepare('INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
    .run('owner@demo.legacypulse.test', pw, 'Thandiwe Moyo', 'owner');
  db.prepare('INSERT INTO profiles (user_id, date_of_birth, phone, bio) VALUES (?, ?, ?, ?)')
    .run(owner.lastInsertRowid, '1968-04-12', '+267 71 234 567', 'Retired teacher, mother of two, grandmother of four. Preserving my story for my family.');

  const beneficiaryUser = db.prepare('INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
    .run('beneficiary@demo.legacypulse.test', pw, 'Kagiso Moyo', 'owner'); // beneficiaries are regular accounts (role=owner) that also happen to be linked as a beneficiary of someone else

  const beneficiary = db.prepare(
    'INSERT INTO beneficiaries (owner_id, full_name, email, relationship, linked_user_id, invite_status) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(owner.lastInsertRowid, 'Kagiso Moyo', 'beneficiary@demo.legacypulse.test', 'Son', beneficiaryUser.lastInsertRowid, 'claimed');

  db.prepare(
    'INSERT INTO beneficiaries (owner_id, full_name, email, relationship, invite_status) VALUES (?, ?, ?, ?, ?)'
  ).run(owner.lastInsertRowid, 'Naledi Moyo', 'naledi@example.test', 'Daughter', 'pending');

  db.prepare(
    'INSERT INTO trusted_contacts (owner_id, full_name, email, status) VALUES (?, ?, ?, ?)'
  ).run(owner.lastInsertRowid, 'Pastor Ernest Kgosi', 'ernest@example.test', 'pending');
  db.prepare(
    'INSERT INTO trusted_contacts (owner_id, full_name, email, status) VALUES (?, ?, ?, ?)'
  ).run(owner.lastInsertRowid, 'Dr. Boitumelo Seretse', 'boitumelo@example.test', 'pending');

  const memories = [
    ['memory', 'How I met your grandfather', 'It was a rainy Tuesday in Gaborone, 1987, at a church fundraiser...', 'family,love'],
    ['story', 'The year the rains failed', 'In 1992, the drought hit our village hard. We learned to share everything...', 'history,resilience'],
    ['instruction', 'Where to find important papers', 'The deed to the house is in the metal box under my bed, together with...', 'practical,important'],
  ];
  for (const [type, title, content, tags] of memories) {
    db.prepare('INSERT INTO memories (owner_id, type, title, content_encrypted, tags) VALUES (?, ?, ?, ?, ?)')
      .run(owner.lastInsertRowid, type, title, encryptField(content), tags);
  }

  const events = [
    ['Born in Francistown', '1968-04-12', 'Milestone'],
    ['Graduated teacher training college', '1989-11-03', 'Career'],
    ['Married Solomon Moyo', '1990-06-16', 'Family'],
    ['Kagiso was born', '1992-02-20', 'Family'],
    ['Retired after 30 years of teaching', '2019-12-15', 'Career'],
  ];
  for (const [title, date, category] of events) {
    db.prepare('INSERT INTO life_events (owner_id, title, event_date, category) VALUES (?, ?, ?, ?)')
      .run(owner.lastInsertRowid, title, date, category);
  }

  // A message already released (immediate) so the beneficiary inbox has content to show.
  db.prepare(
    `INSERT INTO legacy_messages (owner_id, beneficiary_id, title, body_encrypted, release_type, status, released_at)
     VALUES (?, ?, ?, ?, 'immediate', 'released', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`
  ).run(owner.lastInsertRowid, beneficiary.lastInsertRowid, 'A letter for your wedding day',
    encryptField('My dear Kagiso, if you are reading this, I want you to know how proud I am of the man you have become...'));

  // A future scheduled message (pending).
  const future = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365).toISOString();
  db.prepare(
    `INSERT INTO legacy_messages (owner_id, beneficiary_id, title, body_encrypted, release_type, release_at, status)
     VALUES (?, ?, ?, ?, 'scheduled_date', ?, 'pending')`
  ).run(owner.lastInsertRowid, beneficiary.lastInsertRowid, 'Happy 40th birthday',
    encryptField('By the time you read this you will be 40 — I hope you still love biscuits with your tea...'), future);

  console.log('[seed] Demo data created:');
  console.log('  Admin:       admin@demo.legacypulse.test / DemoPass123!');
  console.log('  Owner:       owner@demo.legacypulse.test / DemoPass123!');
  console.log('  Beneficiary: beneficiary@demo.legacypulse.test / DemoPass123!');
}

seed().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
