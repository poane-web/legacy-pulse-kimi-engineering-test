'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config/env');

// V2.0-B (docs/V2_SECURITY_AUDIT.md, H1): tokenVersion is embedded so
// middleware/auth.js can reject access tokens issued before a
// security-relevant event (password change, admin disable, "sign out
// everywhere") even though the token itself hasn't expired yet.
// `user.tokenVersion` must be present on every caller -- see
// routes/auth.routes.js for where it's read from the DB at issuance time.
//
// V2.0-C (docs/V2_0_C_PLAN.md §3): `typ: 'access'` distinguishes a real
// access token from an MFA challenge token (see signMfaChallengeToken
// below). Both may be signed with the same secret, but middleware/auth.js
// explicitly requires typ === 'access', so a challenge token -- issued
// after only the FIRST authentication factor -- can never be used to reach
// a protected route, even though it's a structurally valid, correctly-
// signed JWT. A token with no `typ` claim at all (pre-V2.0-C) is treated
// as 'access' for backward compatibility, mirroring how a missing
// tokenVersion claim defaults to 0.
function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email, tokenVersion: user.tokenVersion, typ: 'access' },
    config.jwtAccessSecret,
    { expiresIn: config.accessTokenTtl }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, config.jwtAccessSecret);
}

// V2.0-C (docs/V2_0_C_PLAN.md §3): short-lived (5 min), single-purpose
// token proving "this caller supplied the correct password for user X",
// issued by POST /auth/login when MFA is enabled, consumed by
// POST /auth/mfa/verify. Deliberately excludes `role` and `tokenVersion`
// claims that a real access token needs -- it isn't one, and isn't meant
// to resemble one beyond sharing a signing key.
function signMfaChallengeToken(userId) {
  return jwt.sign({ sub: userId, typ: 'mfa_challenge' }, config.jwtAccessSecret, { expiresIn: '5m' });
}

function verifyMfaChallengeToken(token) {
  const payload = jwt.verify(token, config.jwtAccessSecret);
  if (payload.typ !== 'mfa_challenge') {
    throw new Error('Not an MFA challenge token');
  }
  return payload;
}

module.exports = { signAccessToken, verifyAccessToken, signMfaChallengeToken, verifyMfaChallengeToken };
