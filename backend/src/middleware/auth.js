'use strict';

const { verifyAccessToken } = require('../utils/jwt');
const { UnauthorizedError } = require('../utils/errors');

/**
 * Verifies the Bearer access token and attaches { id, role, email } to
 * req.user. Does NOT hit the database on every request (stateless JWT) —
 * that's the point of the access/refresh split described in
 * docs/ARCHITECTURE.md. Revocation is handled at refresh time, not here.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return next(new UnauthorizedError('Missing or malformed Authorization header'));
  }
  try {
    const payload = verifyAccessToken(token);
    req.user = { id: payload.sub, role: payload.role, email: payload.email };
    return next();
  } catch (err) {
    return next(new UnauthorizedError('Invalid or expired access token'));
  }
}

module.exports = { requireAuth };
