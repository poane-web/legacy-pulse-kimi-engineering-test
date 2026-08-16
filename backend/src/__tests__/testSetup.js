// Ensures every test run uses a fresh, isolated SQLite file (not the dev
// database), with deterministic test secrets. Required env vars must be
// set BEFORE any application module is required, since config/env.js
// reads process.env at require-time.
'use strict';

const path = require('path');
const os = require('os');

const testDbPath = path.join(os.tmpdir(), `legacy-pulse-test-${process.pid}-${Date.now()}.db`);

process.env.NODE_ENV = 'test';
process.env.DB_PATH = testDbPath;
process.env.UPLOADS_DIR = path.join(os.tmpdir(), `legacy-pulse-test-uploads-${process.pid}-${Date.now()}`);
process.env.JWT_ACCESS_SECRET = 'test-access-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.DATA_ENCRYPTION_KEY = require('crypto').randomBytes(32).toString('base64');
process.env.BCRYPT_COST = '4';
process.env.CLIENT_ORIGIN = 'http://localhost:5173';

// Apply the same forward migrations used by a real deployment. This keeps
// security tests from silently testing a schema older than production.
require('../db/migrate');
const db = require('../db');

afterAll(() => {
  db.close();
  try { require('fs').unlinkSync(testDbPath); } catch (e) { /* ignore */ }
  try { require('fs').unlinkSync(testDbPath + '-wal'); } catch (e) { /* ignore */ }
  try { require('fs').unlinkSync(testDbPath + '-shm'); } catch (e) { /* ignore */ }
});

module.exports = { db };
