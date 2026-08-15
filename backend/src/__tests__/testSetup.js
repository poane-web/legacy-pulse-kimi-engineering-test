// Ensures every test run uses a fresh, isolated SQLite file (not the dev
// database), with deterministic test secrets. Required env vars must be
// set BEFORE any application module is required, since config/env.js
// reads process.env at require-time.
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const testDbPath = path.join(os.tmpdir(), `legacy-pulse-test-${process.pid}-${Date.now()}.db`);

process.env.NODE_ENV = 'test';
process.env.DB_PATH = testDbPath;
process.env.UPLOADS_DIR = path.join(os.tmpdir(), `legacy-pulse-test-uploads-${process.pid}-${Date.now()}`);
process.env.JWT_ACCESS_SECRET = 'test-access-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.DATA_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('base64');
process.env.BCRYPT_COST = '4'; // fast for tests
process.env.CLIENT_ORIGIN = 'http://localhost:5173';

// Apply schema to the fresh test DB.
const db = require('../db');
const schema = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
db.exec(schema);

afterAll(() => {
  db.close();
  try { fs.unlinkSync(testDbPath); } catch (e) { /* ignore */ }
  try { fs.unlinkSync(testDbPath + '-wal'); } catch (e) { /* ignore */ }
  try { fs.unlinkSync(testDbPath + '-shm'); } catch (e) { /* ignore */ }
});

module.exports = { db };
