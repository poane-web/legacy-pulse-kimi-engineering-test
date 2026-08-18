// Builds the Express app without starting the HTTP listener or the cron
// scheduler — this separation lets tests `require('../app')` and drive it
// with supertest without binding a port or running background jobs.
'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const config = require('./config/env');
const db = require('./db');
const { globalLimiter } = require('./middleware/rateLimit');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth.routes');
const usersRoutes = require('./routes/users.routes');
const beneficiariesRoutes = require('./routes/beneficiaries.routes');
const trustedContactsRoutes = require('./routes/trustedContacts.routes');
const memoriesRoutes = require('./routes/memories.routes');
const timelineRoutes = require('./routes/timeline.routes');
const documentsRoutes = require('./routes/documents.routes');
const photosRoutes = require('./routes/photos.routes');
const legacyMessagesRoutes = require('./routes/legacyMessages.routes');
const adminRoutes = require('./routes/admin.routes');
const searchRoutes = require('./routes/search.routes');
const notificationsRoutes = require('./routes/notifications.routes');
const auditRoutes = require('./routes/audit.routes');
const securityRoutes = require('./routes/security.routes');

function createApp() {
  const app = express();

  app.disable('x-powered-by');
  // V2.0-C (docs/V2_0_C_PLAN.md §4, audit finding M5): explicit trust-proxy
  // policy instead of relying on Express's implicit default. 'false'
  // (the default here) means X-Forwarded-For is never honored — req.ip is
  // always the true socket peer, safe for this MVP's direct deployment.
  // Only change this to a specific proxy count/IP list if this app is
  // deployed behind a reverse proxy/load balancer you control — see
  // .env.example for guidance. Blindly trusting it (e.g. 'true') would let
  // a client spoof its own IP for rate-limiting/audit-log purposes.
  app.set('trust proxy', config.trustProxy === 'false' ? false : config.trustProxy);
  app.use(helmet());
  app.use(cors({ origin: config.clientOrigin, credentials: true }));
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());
  // Never log request bodies — they can contain passwords or legacy
  // message content. `morgan('combined')`-style logs method/path/status
  // only, not the body.
  if (config.nodeEnv !== 'test') {
    app.use(morgan(config.nodeEnv === 'production' ? 'combined' : 'dev'));
  }
  app.use('/api', globalLimiter);

  // V2.0-F (docs/V2_0_F_PRODUCTION_READINESS.md): a real liveness/readiness
  // check for orchestrators/load balancers -- verifies the DB connection is
  // actually usable, not just that the HTTP server is up. Returns 503 (not
  // 200) if the DB check fails, so an orchestrator correctly stops routing
  // traffic here instead of getting a false "healthy".
  app.get('/api/health', (req, res) => {
    try {
      db.prepare('SELECT 1').get();
      res.json({ status: 'ok', env: config.nodeEnv, db: 'connected' });
    } catch (err) {
      res.status(503).json({ status: 'error', env: config.nodeEnv, db: 'unavailable' });
    }
  });

  app.use('/api/auth', authRoutes.router);
  app.use('/api/users', usersRoutes);
  app.use('/api/beneficiaries', beneficiariesRoutes);
  app.use('/api/trusted-contacts', trustedContactsRoutes);
  app.use('/api/memories', memoriesRoutes);
  app.use('/api/timeline', timelineRoutes);
  app.use('/api/documents', documentsRoutes);
  app.use('/api/photos', photosRoutes);
  app.use('/api/legacy-messages', legacyMessagesRoutes);
  app.use('/api/admin', adminRoutes);
  app.use('/api/search', searchRoutes);
  app.use('/api/notifications', notificationsRoutes);
  app.use('/api/audit', auditRoutes);
  app.use('/api/security', securityRoutes);

  app.use('/api', notFoundHandler);
  app.use(errorHandler);

  return app;
}

module.exports = createApp;
