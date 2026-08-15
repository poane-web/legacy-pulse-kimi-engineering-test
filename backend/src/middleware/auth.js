'use strict';

const { verifyAccessToken } = require('../utils/jwt');
const { UnauthorizedError } = require('../utils/errors');
const db = require('../db');

// V2.0-B SECURITY FIX (docs/V2_SECURITY_AUDIT.md, finding H1 -- High):
//
// V1's requireAuth was pure JWT signature verification with no DB lookup,
// by design, for statelessness. But that meant disabling a user or
// changing their password only revoked refresh tokens -- an access token
// already in an attacker's (or just-removed employee's) hands stayed fully
// valid for up to its remaining TTL (<=15 min) *after* the very event meant
// to cut off their access.
//
// The fix: every access token embeds the token_version the user had at
// issuance time (see utils/jwt.js). This middleware now does one cheap,
// indexed primary-key lookup per request to compare that embedded version
// against the user's *current* token_version, and rejects the token if
// they don't match. token_version is bumped (see users.routes.js,
// admin.routes.js, security.routes.js) whenever all previously-issued
// access tokens must die immediately: password change, admin-disable, and
// "sign out everywhere".
//
// This is a deliberate, documented trade-off: requireAuth is no longer
// fully stateless (one extra synchronous, indexed SQLite read per
// authenticated request). Given better-sqlite3's in-process synchronous
// reads are on the order of microseconds, this is judged worth it for the
// correctness/security gain on a platform whose entire purpose is
// protecting sensitive legacy content. A future scale-out (V3, see
// V2.0-F) could replace this with a short-lived in-memory/Redis cache of
// token_version per user to avoid a DB hit on every request while keeping
// the same guarantee.
const getUserVersion = db.prepare('SELECT token_version, status FROM users WHERE id = ?');

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return next(new UnauthorizedError('Missing or malformed Authorization header'));
  }
  try {
    const payload = verifyAccessToken(token);
    const current = getUserVersion.get(payload.sub);
    if (!current || current.status === 'disabled') {
      return next(new UnauthorizedError('Account unavailable'));
    }
    // payload.tokenVersion is undefined for tokens issued before this
    // migration; treat that as version 0 so pre-existing valid sessions
    // aren't force-logged-out by the deploy itself, while still being
    // subject to invalidation going forward.
    const tokenVersion = payload.tokenVersion ?? 0;
    if (tokenVersion !== current.token_version) {
      return next(new UnauthorizedError('Session has been invalidated. Please log in again.'));
    }
    req.user = { id: payload.sub, role: payload.role, email: payload.email };
    return next();
  } catch (err) {
    return next(new UnauthorizedError('Invalid or expired access token'));
  }
}

module.exports = { requireAuth };
