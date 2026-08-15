'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config/env');

// V2.0-B (docs/V2_SECURITY_AUDIT.md, H1): tokenVersion is embedded so
// middleware/auth.js can reject access tokens issued before a
// security-relevant event (password change, admin disable, "sign out
// everywhere") even though the token itself hasn't expired yet.
// `user.tokenVersion` must be present on every caller — see
// routes/auth.routes.js for where it's read from the DB at issuance time.
function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email, tokenVersion: user.tokenVersion },
    config.jwtAccessSecret,
    { expiresIn: config.accessTokenTtl }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, config.jwtAccessSecret);
}

module.exports = { signAccessToken, verifyAccessToken };
