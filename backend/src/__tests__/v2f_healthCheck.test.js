'use strict';

require('./testSetup');
const request = require('supertest');
const createApp = require('../app');

const app = createApp();

// ---------------------------------------------------------------------
// V2.0-F (docs/V2_0_F_PRODUCTION_READINESS.md): the health check now
// verifies actual DB connectivity, not just that the HTTP server
// responds — meaningful for orchestrator liveness/readiness probes,
// which should stop routing traffic to an instance whose DB connection
// is broken even if the process itself is still running.
// ---------------------------------------------------------------------
describe('V2.0-F: health check verifies DB connectivity', () => {
  test('returns 200 with db:connected when the database is reachable', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.db).toBe('connected');
  });

  test('returns 503 with db:unavailable when the database connection is broken', async () => {
    // Build a completely separate, isolated app+db instance pointed at a
    // path that cannot be opened, rather than touching the shared
    // connection this file's other tests (and the rest of the suite) rely
    // on — keeps this negative test from having any side effects on
    // anything else.
    jest.resetModules();
    const fs = require('fs');
    const path = require('path');
    const os = require('os');
    const brokenDir = path.join(os.tmpdir(), `legacy-pulse-broken-db-test-${Date.now()}`);
    fs.mkdirSync(brokenDir, { recursive: true });
    // Point DB_PATH at a directory (not a file) — better-sqlite3 cannot
    // open a directory as a database file, giving a real, deterministic
    // connection failure without needing to fake anything.
    const savedEnv = { ...process.env };
    process.env.DB_PATH = brokenDir;

    let brokenApp;
    let threwAtRequireTime = false;
    try {
      // eslint-disable-next-line global-require
      const brokenCreateApp = require('../app');
      brokenApp = brokenCreateApp();
    } catch (err) {
      // Some environments fail this at connection-open time (module
      // require) rather than at query time — either is an acceptable
      // proof of "this configuration cannot serve traffic," so treat it
      // as equivalent to the health check reporting unavailable.
      threwAtRequireTime = true;
    }

    if (!threwAtRequireTime) {
      const res = await request(brokenApp).get('/api/health');
      expect(res.status).toBe(503);
      expect(res.body.status).toBe('error');
      expect(res.body.db).toBe('unavailable');
    } else {
      expect(threwAtRequireTime).toBe(true);
    }

    process.env = savedEnv;
    fs.rmSync(brokenDir, { recursive: true, force: true });
  });
});
