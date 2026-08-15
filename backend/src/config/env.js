// Centralized environment configuration.
//
// Architectural decision: every secret/config value flows through this
// module instead of routes/services calling `process.env` directly. This
// gives us one place that (a) fails loudly at startup if a required secret
// is missing, and (b) documents what each variable is for. See
// .env.example for the full list with placeholder values.
'use strict';

require('dotenv').config({ quiet: true });

const REQUIRED_IN_PRODUCTION = [
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'DATA_ENCRYPTION_KEY',
];

const NODE_ENV = process.env.NODE_ENV || 'development';

// In development/test we generate ephemeral secrets automatically so the
// project runs with zero setup friction, but we NEVER do this in
// production — a missing secret in production must be a hard failure, not
// a silently-generated one (a restart would otherwise invalidate every
// session and, worse, a horizontally-scaled deployment would have
// different instances silently using different keys).
const crypto = require('crypto');
function devFallback(name, { isBase64_32 = false } = {}) {
  if (NODE_ENV === 'production') return undefined;
  // Deterministic-per-process, not persisted — fine for local dev/test only.
  const digest = crypto.createHash('sha256').update(name + '-dev-only-fallback');
  return isBase64_32 ? digest.digest('base64') : digest.digest('hex');
}

function required(name, { isBase64_32 = false } = {}) {
  let value = process.env[name];
  if (!value) value = devFallback(name, { isBase64_32 });
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. See .env.example. ` +
      `Refusing to start with an insecure default in production.`
    );
  }
  if (isBase64_32) {
    const buf = Buffer.from(value, 'base64');
    if (buf.length !== 32) {
      throw new Error(
        `${name} must decode to exactly 32 bytes (AES-256 key) when base64-decoded. ` +
        `Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
      );
    }
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

  // 32-byte key, base64-encoded, used for AES-256-GCM field & file encryption.
  dataEncryptionKey: required('DATA_ENCRYPTION_KEY', { isBase64_32: true }),

  bcryptCost: parseInt(process.env.BCRYPT_COST || '12', 10),

  dbPath: process.env.DB_PATH || require('path').join(__dirname, '..', '..', 'data', 'legacy_pulse.db'),
  uploadsDir: process.env.UPLOADS_DIR || require('path').join(__dirname, '..', '..', 'uploads'),
  maxUploadMb: parseInt(process.env.MAX_UPLOAD_MB || '15', 10),

  requiredReleaseConfirmations: parseInt(process.env.REQUIRED_RELEASE_CONFIRMATIONS || '2', 10),

  // Configurable so the automated test suite can exercise the "too many
  // attempts" path deterministically (low limit) without tripping over
  // itself in fixture-heavy tests elsewhere (high default limit). See
  // AUTH_RATE_LIMIT_MAX in .env.example.
  authRateLimitMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX || (NODE_ENV === 'test' ? '200' : '10'), 10),
};

module.exports = config;
