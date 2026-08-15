'use strict';

const { verifyAccessToken } = require('../utils/jwt');
const { UnauthorizedError } = require('../utils/errors');
const db = require('../db');

/**
 * Verifies the bearer token and re-checks the account in the database.
 * Disabling an account or changing its password therefore invalidates an
 * already-issued access token immediately instead of waiting for its TTL.
 * Role/email are read from current DB state rather than trusted from a
 * potentially stale JWT claim.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return next(new UnauthorizedError('Missing or malformed Authorization header'));
  try {
    const payload = verifyAccessToken(token);
    const user = db.prepare('SELECT id, email, role, status FROM users WHERE id = ?').get(payload.sub);
    if (!user || user.status !== 'active') throw new Error('account_unavailable');
    req.user = { id: user.id, role: user.role, email: user.email };
    return next();
  } catch (err) {
    return next(new UnauthorizedError('Invalid, expired, or revoked access token'));
  }
}

module.exports = { requireAuth };
