// Rate limiting. In-memory store (express-rate-limit default) — sufficient
// for a single-process MVP; documented in the threat model that a
// multi-instance production deployment needs a shared store (Redis).
'use strict';

const rateLimit = require('express-rate-limit');

const config = require('../config/env');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: config.authRateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many attempts. Please try again later.' } },
});

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Too many requests. Please slow down.' } },
});

module.exports = { authLimiter, globalLimiter };
