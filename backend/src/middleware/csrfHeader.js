// V2.0-B SECURITY FIX (docs/V2_SECURITY_AUDIT.md, finding M2 -- Medium):
//
// Every state-changing route in this app except POST /api/auth/refresh and
// POST /api/auth/logout requires a Bearer access token, which a
// cross-site page cannot attach to a request on the victim's behalf — that
// alone rules out classic CSRF for the vast majority of the API surface.
// Those two endpoints are the exception: by necessity they authenticate
// via the httpOnly refresh cookie ALONE (refresh has to work before the
// caller has an access token at all).
//
// The refresh cookie already sets SameSite=Strict, which is a strong
// primary defense (browsers won't attach it to any cross-site request,
// including a classic HTML <form> POST). This middleware adds
// defense-in-depth on top of that: it requires a custom request header
// that a plain cross-site <form> submission cannot set (only same-origin
// JavaScript using fetch/XHR can add custom headers, and doing so
// cross-site would itself require a CORS preflight that our strict
// same-origin CORS policy — see app.js — would reject). This is the
// standard "custom header" CSRF mitigation pattern and adds no new
// dependency.
'use strict';

const { ForbiddenError } = require('../utils/errors');

const REQUIRED_HEADER = 'x-legacy-pulse-client';

function requireCsrfHeader(req, res, next) {
  if (req.headers[REQUIRED_HEADER] !== '1') {
    return next(new ForbiddenError('Missing required client header'));
  }
  next();
}

module.exports = { requireCsrfHeader, REQUIRED_HEADER };
