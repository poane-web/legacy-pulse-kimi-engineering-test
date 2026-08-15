// Central error handler. Production responses never leak stack traces or
// internal error details (see docs/THREAT_MODEL.md T11) — those are logged
// server-side only.
'use strict';

const config = require('../config/env');

function notFoundHandler(req, res) {
  res.status(404).json({ error: { message: 'Route not found' } });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;
  const isServerError = statusCode >= 500;

  if (isServerError) {
    // eslint-disable-next-line no-console
    console.error('[error]', err);
  }

  const body = {
    error: {
      message: isServerError && config.nodeEnv === 'production'
        ? 'An unexpected error occurred'
        : err.message,
      code: err.code,
    },
  };

  if (config.nodeEnv !== 'production' && err.stack && isServerError) {
    body.error.stack = err.stack;
  }

  res.status(statusCode).json(body);
}

module.exports = { notFoundHandler, errorHandler };
