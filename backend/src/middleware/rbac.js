// Role-based access control + resource-ownership enforcement.
//
// Design note: rather than every route handler re-implementing
// `if (row.owner_id !== req.user.id) return 403`, resource routes use
// `requireOwnership(loader)` which loads the row once, attaches it to
// `req.resource`, and rejects if the caller doesn't own it. This
// centralizes the highest-value authorization check in the app (IDOR
// prevention, see docs/THREAT_MODEL.md T7) so it can't be silently skipped
// on a new endpoint.
'use strict';

const { ForbiddenError, NotFoundError } = require('../utils/errors');
const { logAudit } = require('../utils/audit');

function requireRole(...roles) {
  return function (req, res, next) {
    if (!req.user || !roles.includes(req.user.role)) {
      return next(new ForbiddenError('You do not have permission to perform this action'));
    }
    next();
  };
}

/**
 * @param {(req) => object|undefined} loader - synchronous DB lookup returning
 *   a row with an `owner_id` column, or undefined if not found.
 */
function requireOwnership(loader, targetType) {
  return function (req, res, next) {
    const resource = loader(req);
    if (!resource) return next(new NotFoundError(`${targetType || 'Resource'} not found`));
    if (resource.owner_id !== req.user.id) {
      logAudit({
        actorUserId: req.user.id,
        action: `${targetType || 'resource'}.unauthorized_access_attempt`,
        targetType,
        targetId: resource.id,
        ip: req.ip,
      });
      return next(new ForbiddenError('You do not have access to this resource'));
    }
    req.resource = resource;
    next();
  };
}

module.exports = { requireRole, requireOwnership };
