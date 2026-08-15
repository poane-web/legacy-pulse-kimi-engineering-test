// Append-only audit log writer. Every security-relevant action in the app
// (auth events, resource create/delete, release events, unauthorized
// access attempts, admin actions) should call this. There is deliberately
// no update/delete function exported — see docs/THREAT_MODEL.md (T16).
'use strict';

const db = require('../db');

const insertStmt = db.prepare(`
  INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, ip_address, metadata_json)
  VALUES (@actor_user_id, @action, @target_type, @target_id, @ip_address, @metadata_json)
`);

/**
 * @param {object} opts
 * @param {number|null} opts.actorUserId
 * @param {string} opts.action - dot-namespaced, e.g. 'auth.login_success'
 * @param {string} [opts.targetType]
 * @param {number} [opts.targetId]
 * @param {string} [opts.ip]
 * @param {object} [opts.metadata] - MUST NOT contain decrypted content or secrets
 */
function logAudit({ actorUserId = null, action, targetType = null, targetId = null, ip = null, metadata = null }) {
  insertStmt.run({
    actor_user_id: actorUserId,
    action,
    target_type: targetType,
    target_id: targetId,
    ip_address: ip,
    metadata_json: metadata ? JSON.stringify(metadata) : null,
  });
}

module.exports = { logAudit };
