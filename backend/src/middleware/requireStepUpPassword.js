// V3 follow-up (docs/security/V3-THREAT-MODEL.md, finding "Step-up
// authentication gap" under category G): a reusable middleware for
// requiring password re-confirmation on high-consequence actions.
//
// Before this, the pattern was duplicated inline in three places
// (users.routes.js password change, users.routes.js account deletion,
// security.routes.js MFA disable) with no shared implementation, and NOT
// applied at all to two other high-consequence actions -- revoking a
// trusted contact and deleting a beneficiary -- despite both directly
// affecting release authority. An attacker with a stolen (but valid,
// unexpired) access token could silently strip an account's
// trusted-contact protections without ever knowing the account password.
//
// This middleware centralizes the check so it's applied consistently
// going forward, and is now also applied to the two previously-unguarded
// routes (see trustedContacts.routes.js, beneficiaries.routes.js).
'use strict';

const bcrypt = require('bcrypt');
const db = require('../db');
const { UnauthorizedError, BadRequestError } = require('../utils/errors');

function requireStepUpPassword() {
  return async function (req, res, next) {
    const { password } = req.body || {};
    if (!password) {
      return next(new BadRequestError('Password confirmation is required for this action'));
    }
    try {
      const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
      const matches = await bcrypt.compare(password, user.password_hash);
      if (!matches) {
        return next(new UnauthorizedError('Password is incorrect'));
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { requireStepUpPassword };
