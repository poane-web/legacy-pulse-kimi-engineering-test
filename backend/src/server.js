'use strict';

const path = require('path');
const express = require('express');

const config = require('./config/env');
const db = require('./db');
const createApp = require('./app');
const { startReleaseScheduler } = require('./services/releaseScheduler');

const app = createApp();

// Serve the built-less static frontend. Kept as a separate `express.static`
// mount rather than merging into app.js, since the frontend is an
// optional, swappable concern (see docs/ARCHITECTURE.md "clean
// separation") — the API works standalone (e.g. for the test suite) without it.
const frontendDir = path.join(__dirname, '..', '..', 'frontend', 'public');
app.use(express.static(frontendDir));
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

const server = app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`[server] Legacy Pulse API listening on port ${config.port} (${config.nodeEnv})`);
});

const scheduledTask = startReleaseScheduler();

// V2.0-F (docs/V2_0_F_PRODUCTION_READINESS.md): graceful shutdown.
// Without this, a SIGTERM (which is what every container
// orchestrator/process manager sends before killing a process, e.g. during
// a deploy or autoscaling event) would kill in-flight requests mid-response
// and leave the SQLite WAL file in whatever state it happened to be in
// rather than cleanly checkpointed. This is real correctness/reliability
// hardening achievable without any external infrastructure — unlike most
// of V2.0-F, which explicitly requires infrastructure this MVP doesn't have.
let shuttingDown = false;
function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  // eslint-disable-next-line no-console
  console.log(`[server] Received ${signal}, shutting down gracefully...`);

  scheduledTask.stop();

  server.close((err) => {
    if (err) {
      // eslint-disable-next-line no-console
      console.error('[server] Error during HTTP server close', err);
    }
    try {
      db.close();
      // eslint-disable-next-line no-console
      console.log('[server] Database connection closed. Exiting.');
    } catch (dbErr) {
      // eslint-disable-next-line no-console
      console.error('[server] Error closing database', dbErr);
    }
    process.exit(err ? 1 : 0);
  });

  // Safety net: if something is still hanging after 10s (e.g. a stuck
  // request), force-exit rather than let the process hang forever and
  // block a deploy/restart.
  setTimeout(() => {
    // eslint-disable-next-line no-console
    console.error('[server] Graceful shutdown timed out after 10s, forcing exit.');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = { server, gracefulShutdown };
