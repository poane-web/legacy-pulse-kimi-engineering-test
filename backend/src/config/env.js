'use strict';

require('dotenv').config({ quiet: true });

const NODE_ENV = process.env.NODE_ENV || 'development';
const crypto = require('crypto');

function devFallback(name, { isBase64_32 = false } = {}) {
  // Development/test convenience only. Never derive secrets from source code:
  // this repository is public, so deterministic fallbacks would be forgeable.
  if (NODE_ENV === 'production') return undefined;
  const bytes = isBase64_32 ? crypto.randomBytes(32) : crypto.randomBytes(48);
  return isBase64_32 ? bytes.toString('base64') : bytes.toString('hex');
}

function required(name, { isBase64_32 = false } = {}) {
  let value = process.env[name];
  if (!value) value = devFallback(name, { isBase64_32 });
  if (!value) {
    throw new Error(`Missing required environment variable ${name}. Refusing to start without a secret.`);
  }
  if (isBase64_32) {
    const buf = Buffer.from(value, 'base64');
    if (buf.length !== 32) throw new Error(`${name} must decode to exactly 32 bytes.`);
  }
  return value;
}

const config = {
  nodeEnv: NODE_ENV,
  port: parseInt(process.env.PORT || '4000', 10),
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  jwtAccessSecret: required('JWT_ACCESS_SECRET'),
  jwtRefreshSecret: required('JWT_REFRESH_SECRET'),
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || '15m',
  refreshTokenTtlDays: parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || '7', 10),
  dataEncryptionKey: required('DATA_ENCRYPTION_KEY', { isBase64_32: true }),
  bcryptCost: parseInt(process.env.BCRYPT_COST || '12', 10),
  dbPath: process.env.DB_PATH || require('path').join(__dirname, '..', '..', 'data', 'legacy_pulse.db'),
  uploadsDir: process.env.UPLOADS_DIR || require('path').join(__dirname, '..', '..', 'uploads'),
  maxUploadMb: parseInt(process.env.MAX_UPLOAD_MB || '15', 10),
  requiredReleaseConfirmations: parseInt(process.env.REQUIRED_RELEASE_CONFIRMATIONS || '2', 10),
  authRateLimitMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX || (NODE_ENV === 'test' ? '200' : '10'), 10),
};

module.exports = config;
