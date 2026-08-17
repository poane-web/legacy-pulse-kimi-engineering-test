'use strict';

const express = require('express');
const multer = require('multer');
const { body, query } = require('express-validator');

const db = require('../db');
const config = require('../config/env');
const asyncHandler = require('../utils/asyncHandler');
const { requireAuth } = require('../middleware/auth');
const { requireOwnership } = require('../middleware/rbac');
const { handleValidation } = require('../middleware/validate');
const { logAudit } = require('../utils/audit');
const { encryptField, decryptField } = require('../utils/crypto');
const { ownerContext } = require('../utils/encryptionContext');
const storage = require('../services/storage');
const { contentMatchesDeclaredType } = require('../utils/fileSignature');
const { BadRequestError } = require('../utils/errors');

const router = express.Router();
router.use(requireAuth);

const ALLOWED_IMAGE_MIME_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadMb * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
      return cb(new BadRequestError(`File type ${file.mimetype} is not allowed for photos`));
    }
    cb(null, true);
  },
});

function toDTO(row) {
  return {
    id: row.id,
    caption: row.caption_encrypted ? decryptField(row.caption_encrypted, ownerContext('photos', 'caption_encrypted', row.owner_id)) : null,
    mimeType: row.mime_type,
    sizeBytes: row.size_bytes,
    memoryId: row.memory_id,
    lifeEventId: row.life_event_id,
    createdAt: row.created_at,
  };
}

router.get(
  '/',
  [
    query('memoryId').optional().isInt(),
    query('lifeEventId').optional().isInt(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    // V2.0-E (docs/V2_0_E_PLAN.md §2): scoped filtering so a client can
    // ask "photos for this memory" / "photos for this life event"
    // directly, instead of fetching every photo and filtering client-side.
    let rows;
    if (req.query.memoryId) {
      const m = db.prepare('SELECT owner_id FROM memories WHERE id = ?').get(req.query.memoryId);
      if (!m || m.owner_id !== req.user.id) throw new BadRequestError('Invalid memoryId');
      rows = db.prepare('SELECT * FROM photos WHERE owner_id = ? AND memory_id = ? ORDER BY created_at DESC').all(req.user.id, req.query.memoryId);
    } else if (req.query.lifeEventId) {
      const e = db.prepare('SELECT owner_id FROM life_events WHERE id = ?').get(req.query.lifeEventId);
      if (!e || e.owner_id !== req.user.id) throw new BadRequestError('Invalid lifeEventId');
      rows = db.prepare('SELECT * FROM photos WHERE owner_id = ? AND life_event_id = ? ORDER BY created_at DESC').all(req.user.id, req.query.lifeEventId);
    } else {
      rows = db.prepare('SELECT * FROM photos WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
    }
    res.json({ photos: rows.map(toDTO) });
  })
);

router.post(
  '/',
  upload.single('file'),
  [
    body('caption').optional().isString().isLength({ max: 1000 }),
    body('memoryId').optional().isInt(),
    body('lifeEventId').optional().isInt(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    if (!req.file) throw new BadRequestError('No file provided (field name must be "file")');
    // V2.0-B (H4): verify actual bytes match the declared (and allowed)
    // image type — see documents.routes.js for the full rationale.
    if (!contentMatchesDeclaredType(req.file.buffer, req.file.mimetype)) {
      logAudit({ actorUserId: req.user.id, action: 'photo.upload_rejected_signature_mismatch', ip: req.ip, metadata: { declaredMimeType: req.file.mimetype } });
      throw new BadRequestError('File content does not match its declared type');
    }

    // V2.0-E (docs/V2_0_E_PLAN.md §1): a photo may illustrate a specific
    // memory OR a specific life event, not both at once — the product
    // concept doesn't define what "both" would mean. Enforced here at the
    // application layer rather than a DB CHECK constraint (see the plan
    // doc for why: SQLite can't add one to an existing table without a
    // risky full-table rebuild).
    if (req.body.memoryId && req.body.lifeEventId) {
      throw new BadRequestError('A photo can be attached to a memory or a life event, not both');
    }

    // If linking to a memory/life-event, verify ownership to prevent
    // attaching a photo to another user's resource.
    if (req.body.memoryId) {
      const m = db.prepare('SELECT owner_id FROM memories WHERE id = ?').get(req.body.memoryId);
      if (!m || m.owner_id !== req.user.id) throw new BadRequestError('Invalid memoryId');
    }
    if (req.body.lifeEventId) {
      const e = db.prepare('SELECT owner_id FROM life_events WHERE id = ?').get(req.body.lifeEventId);
      if (!e || e.owner_id !== req.user.id) throw new BadRequestError('Invalid lifeEventId');
    }

    const fileContext = ownerContext('photos', 'file', req.user.id);
    const saved = storage.save(req.file.buffer, fileContext);
    const info = db.prepare(
      `INSERT INTO photos
        (owner_id, memory_id, life_event_id, caption_encrypted, stored_filename, mime_type, size_bytes, file_iv, file_auth_tag, enc_format, checksum_sha256)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      req.user.id,
      req.body.memoryId || null,
      req.body.lifeEventId || null,
      req.body.caption ? encryptField(req.body.caption, ownerContext('photos', 'caption_encrypted', req.user.id)) : null,
      saved.storedFilename,
      req.file.mimetype,
      saved.sizeBytes,
      saved.iv,
      saved.authTag,
      saved.format,
      saved.checksum
    );

    logAudit({ actorUserId: req.user.id, action: 'photo.uploaded', targetType: 'photo', targetId: info.lastInsertRowid, ip: req.ip });
    res.status(201).json({ photo: toDTO(db.prepare('SELECT * FROM photos WHERE id = ?').get(info.lastInsertRowid)) });
  })
);

router.get(
  '/:id/download',
  requireOwnership((req) => db.prepare('SELECT * FROM photos WHERE id = ?').get(req.params.id), 'photo'),
  asyncHandler(async (req, res) => {
    const row = req.resource;
    const plaintext = storage.read(row.stored_filename, row.file_iv, row.file_auth_tag, row.checksum_sha256, row.enc_format, ownerContext('photos', 'file', row.owner_id));
    // V2.0-B (M4): documents.routes.js already logged successful downloads;
    // photos didn't, leaving an audit-coverage gap for a resource type this
    // product's activity log is supposed to cover.
    logAudit({ actorUserId: req.user.id, action: 'photo.downloaded', targetType: 'photo', targetId: row.id, ip: req.ip });
    res.setHeader('Content-Type', row.mime_type);
    res.send(plaintext);
  })
);

router.delete(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM photos WHERE id = ?').get(req.params.id), 'photo'),
  asyncHandler(async (req, res) => {
    storage.remove(req.resource.stored_filename);
    db.prepare('DELETE FROM photos WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'photo.deleted', targetType: 'photo', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

// V2.0-E (docs/V2_0_E_PLAN.md §3): lets an owner move a photo between "no
// context," "attached to memory X," or "attached to life event Y" without
// having to delete and re-upload identical bytes just to change metadata.
router.put(
  '/:id/attachment',
  requireOwnership((req) => db.prepare('SELECT * FROM photos WHERE id = ?').get(req.params.id), 'photo'),
  [
    body('memoryId').optional({ nullable: true }).isInt(),
    body('lifeEventId').optional({ nullable: true }).isInt(),
  ],
  handleValidation,
  asyncHandler(async (req, res) => {
    const { memoryId, lifeEventId } = req.body;
    if (memoryId && lifeEventId) {
      throw new BadRequestError('A photo can be attached to a memory or a life event, not both');
    }
    if (memoryId) {
      const m = db.prepare('SELECT owner_id FROM memories WHERE id = ?').get(memoryId);
      if (!m || m.owner_id !== req.user.id) throw new BadRequestError('Invalid memoryId');
    }
    if (lifeEventId) {
      const e = db.prepare('SELECT owner_id FROM life_events WHERE id = ?').get(lifeEventId);
      if (!e || e.owner_id !== req.user.id) throw new BadRequestError('Invalid lifeEventId');
    }

    db.prepare('UPDATE photos SET memory_id = ?, life_event_id = ? WHERE id = ?')
      .run(memoryId || null, lifeEventId || null, req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'photo.reattached', targetType: 'photo', targetId: Number(req.params.id), ip: req.ip });
    res.json({ photo: toDTO(db.prepare('SELECT * FROM photos WHERE id = ?').get(req.params.id)) });
  })
);

module.exports = router;
