'use strict';

const path = require('path');
const express = require('express');

const config = require('./config/env');
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

app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`[server] Legacy Pulse API listening on port ${config.port} (${config.nodeEnv})`);
});

startReleaseScheduler();
