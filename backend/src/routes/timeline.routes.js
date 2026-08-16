'use strict';

const express = require('express');
const { body } = require('express-validator');

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

function toDTO(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description_encrypted ? decryptField(row.description_encrypted, ownerContext('life_events', 'description_encrypted', row.owner_id)) : null,
    eventDate: row.event_date,
    category: row.category,
    createdAt: row.created_at,
  };
}

router.get(
  '/',
  asyncHandler(async (req, res) => {
    const rows = db.prepare('SELECT * FROM life_events WHERE owner_id = ? ORDER BY event_date ASC').all(req.user.id);
    res.json({ events: rows.map(toDTO) });
  })
);

router.post(
  '/',
  [
    body('title').trim().isLength({ min: 1, max: 300 }),
    body('eventDate').isISO8601().withMessage('must be a valid date'),
    body('description').optional().isString().isLength({ max: 20000 }),
    body('category').optional().isString().isLength({ max: 100 }),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { title, eventDate, description, category } = req.body;
    const info = db.prepare(
      'INSERT INTO life_events (owner_id, title, description_encrypted, event_date, category) VALUES (?, ?, ?, ?, ?)'
    ).run(req.user.id, title, description ? encryptField(description, ownerContext('life_events', 'description_encrypted', req.user.id)) : null, eventDate, category || null);
    logAudit({ actorUserId: req.user.id, action: 'life_event.created', targetType: 'life_event', targetId: info.lastInsertRowid, ip: req.ip });
    res.status(201).json({ event: toDTO(db.prepare('SELECT * FROM life_events WHERE id = ?').get(info.lastInsertRowid)) });
  })
);

router.put(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM life_events WHERE id = ?').get(req.params.id), 'life_event'),
  [
    body('title').optional().trim().isLength({ min: 1, max: 300 }),
    body('eventDate').optional().isISO8601(),
    body('description').optional().isString().isLength({ max: 20000 }),
    body('category').optional().isString().isLength({ max: 100 }),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { title, eventDate, description, category } = req.body;
    db.prepare(
      `UPDATE life_events SET
        title = COALESCE(?, title),
        event_date = COALESCE(?, event_date),
        description_encrypted = COALESCE(?, description_encrypted),
        category = COALESCE(?, category)
       WHERE id = ?`
    ).run(title ?? null, eventDate ?? null, description !== undefined ? encryptField(description, ownerContext('life_events', 'description_encrypted', req.user.id)) : null, category ?? null, req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'life_event.updated', targetType: 'life_event', targetId: Number(req.params.id), ip: req.ip });
    res.json({ event: toDTO(db.prepare('SELECT * FROM life_events WHERE id = ?').get(req.params.id)) });
  })
);

router.delete(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM life_events WHERE id = ?').get(req.params.id), 'life_event'),
  asyncHandler(async (req, res) => {
    db.prepare('DELETE FROM life_events WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'life_event.deleted', targetType: 'life_event', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

module.exports = router;
