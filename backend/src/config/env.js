// Centralized environment configuration.
//
// Architectural decision: every secret/config value flows through this
// module instead of routes/services calling `process.env` directly. This
// gives us one place that (a) fails loudly at startup if a required secret
// is missing, and (b) documents what each variable is for. See
// .env.example for the full list with placeholder values.
'use strict';

require('dotenv').config({ quiet: true });

const crypto = require('crypto');

const NODE_ENV = process.env.NODE_ENV || 'development';

// ---------------------------------------------------------------------
// V2 SECURITY FIX (docs/V2_SECURITY_AUDIT.md, finding C1 -- Critical)
//
// V1 generated a *deterministic* fallback secret outside NODE_ENV=production
// by hashing a fixed, public string (sha256(name + '-dev-only-fallback')).
// Because that string is public (this repository), anyone could compute
// the exact same secret offline. If the app were ever run with NODE_ENV
// unset, 'development', 'staging', or anything other than the literal
// string 'production' -- a common real-world misconfiguration -- an
// attacker who simply read this source code could forge admin JWTs and
// derive the data encryption key, with zero credentials.
//
// The fix: the fallback is now a RANDOM value (crypto.randomBytes), unique
// per process start, never derivable from source code, and never
// persisted. This preserves the original developer-experience goal (the
// app still runs immediately with no .env file) while removing the
// critical vulnerability. The trade-off -- sessions/encrypted data don't
// survive a process restart without a real .env -- is an acceptable,
// intentional cost for local development; it is not a change to any
// production security guarantee (production still requires real secrets
// and refuses to start without them, exactly as before).
// ---------------------------------------------------------------------
let warnedAboutEphemeralSecrets = false;
function ephemeralDevFallback(name, { isBase64_32 = false } = {}) {
  if (NODE_ENV === 'production') return undefined;
  if (!warnedAboutEphemeralSecrets && NODE_ENV !== 'test') {
    // eslint-disable-next-line no-console
    console.warn(
      '\n[config] WARNING: one or more security secrets are not set in the environment.\n' +
      '  Using RANDOM, process-local, non-persistent fallback values.\n' +
      '  This is fine for local development only -- set real values in a\n' +
      '  .env file (see .env.example) before anything resembling a real\n' +
      '  deployment. These fallbacks change every restart and invalidate\n' +
      '  all sessions and encrypted data when they do.\n'
    );
    warnedAboutEphemeralSecrets = true;
  }
  return isBase64_32 ? crypto.randomBytes(32).toString('base64') : crypto.randomBytes(48).toString('hex');
}

function required(name, { isBase64_32 = false } = {}) {
  let value = process.env[name];
  if (!value) value = ephemeralDevFallback(name, { isBase64_32 });
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

  // V2.0-B (M3): seed.js refuses to run against a database started with
  // NODE_ENV=production unless this is explicitly set -- see db/seed.js.
  allowProdSeed: process.env.ALLOW_PROD_SEED === 'true',

  // V2.0-C (docs/V2_0_C_PLAN.md §2): account-level lockout, layered on top
  // of the existing IP-based rate limiter (auth.routes.js), to slow a
  // distributed low-and-slow attacker targeting one account from many IPs.
  accountLockoutThreshold: parseInt(process.env.ACCOUNT_LOCKOUT_THRESHOLD || '5', 10),
  accountLockoutMinutes: parseInt(process.env.ACCOUNT_LOCKOUT_MINUTES || '15', 10),

  // V2.0-C (docs/V2_0_C_PLAN.md §4): explicit trust-proxy policy. Default
  // 'false' is the safe choice for this MVP's direct-to-internet,
  // single-process deployment — Express will not honor X-Forwarded-For at
  // all, so req.ip is always the true socket peer address, never
  // spoofable via that header. Only set this if genuinely deployed behind
  // a reverse proxy/load balancer you control — see .env.example.
  trustProxy: process.env.TRUST_PROXY || 'false',
};

module.exports = config;
