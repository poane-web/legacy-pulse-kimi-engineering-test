'use strict';

const express = require('express');
const { body, query } = require('express-validator');

const db = require('../db');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { requireOwnership } = require('../middleware/rbac');
const { handleValidation } = require('../middleware/validate');
const { logAudit } = require('../utils/audit');
const { encryptField, decryptField } = require('../utils/crypto');
const { ownerContext } = require('../utils/encryptionContext');

const router = express.Router();
router.use(requireAuth);

const TYPES = ['memory', 'story', 'instruction'];

function toDTO(row) {
  return {
    id: row.id,
    type: row.type,
    title: row.title,
    content: decryptField(row.content_encrypted, ownerContext('memories', 'content_encrypted', row.owner_id)),
    tags: row.tags ? row.tags.split(',').filter(Boolean) : [],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

router.get(
  '/',
  [query('type').optional().isIn(TYPES)],
  handleValidation,
  asyncHandler(async (req, res) => {
    const rows = req.query.type
      ? db.prepare('SELECT * FROM memories WHERE owner_id = ? AND type = ? ORDER BY created_at DESC').all(req.user.id, req.query.type)
      : db.prepare('SELECT * FROM memories WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json({ memories: rows.map(toDTO) });
  })
);

router.get(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM memories WHERE id = ?').get(req.params.id), 'memory'),
  asyncHandler(async (req, res) => {
    res.json({ memory: toDTO(req.resource) });
  })
);

router.post(
  '/',
  [
    body('type').isIn(TYPES),
    body('title').trim().isLength({ min: 1, max: 300 }),
    body('content').isString().isLength({ min: 1, max: 50000 }),
    body('tags').optional().isArray(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { type, title, content, tags } = req.body;
    const info = db.prepare(
      'INSERT INTO memories (owner_id, type, title, content_encrypted, tags) VALUES (?, ?, ?, ?, ?)'
    ).run(req.user.id, type, title, encryptField(content, ownerContext('memories', 'content_encrypted', req.user.id)), Array.isArray(tags) ? tags.join(',') : null);
    logAudit({ actorUserId: req.user.id, action: `${type}.created`, targetType: type, targetId: info.lastInsertRowid, ip: req.ip });
    const row = db.prepare('SELECT * FROM memories WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ memory: toDTO(row) });
  })
);

router.put(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM memories WHERE id = ?').get(req.params.id), 'memory'),
  [
    body('title').optional().trim().isLength({ min: 1, max: 300 }),
    body('content').optional().isString().isLength({ min: 1, max: 50000 }),
    body('tags').optional().isArray(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { title, content, tags } = req.body;
    db.prepare(
      `UPDATE memories SET
        title = COALESCE(?, title),
        content_encrypted = COALESCE(?, content_encrypted),
        tags = COALESCE(?, tags),
        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
       WHERE id = ?`
    ).run(title ?? null, content !== undefined ? encryptField(content, ownerContext('memories', 'content_encrypted', req.user.id)) : null, Array.isArray(tags) ? tags.join(',') : null, req.params.id);
    logAudit({ actorUserId: req.user.id, action: `${req.resource.type}.updated`, targetType: req.resource.type, targetId: Number(req.params.id), ip: req.ip });
    res.json({ memory: toDTO(db.prepare('SELECT * FROM memories WHERE id = ?').get(req.params.id)) });
  })
);

router.delete(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM memories WHERE id = ?').get(req.params.id), 'memory'),
  asyncHandler(async (req, res) => {
    db.prepare('DELETE FROM memories WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: `${req.resource.type}.deleted`, targetType: req.resource.type, targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

module.exports = router;
