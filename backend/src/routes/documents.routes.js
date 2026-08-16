'use strict';

const express = require('express');
const multer = require('multer');
const { body } = require('express-validator');

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

// Allow-list of MIME types accepted for "documents" (broader than photos,
// but still restricted — no executables/scripts). See docs/THREAT_MODEL.md T10.
const ALLOWED_DOCUMENT_MIME_TYPES = new Set([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
  'image/png',
  'image/jpeg',
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadMb * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_DOCUMENT_MIME_TYPES.has(file.mimetype)) {
      return cb(new BadRequestError(`File type ${file.mimetype} is not allowed`));
    }
    cb(null, true);
  },
});

function toDTO(row) {
  return {
    id: row.id,
    filename: decryptField(row.original_filename_encrypted, ownerContext('documents', 'original_filename_encrypted', row.owner_id)),
    mimeType: row.mime_type,
    sizeBytes: row.size_bytes,
    description: row.description_encrypted ? decryptField(row.description_encrypted, ownerContext('documents', 'description_encrypted', row.owner_id)) : null,
    createdAt: row.created_at,
  };
}

router.get(
  '/',
  asyncHandler(async (req, res) => {
    const rows = db.prepare('SELECT * FROM documents WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json({ documents: rows.map(toDTO) });
  })
);

router.post(
  '/',
  upload.single('file'),
  [body('description').optional().isString().isLength({ max: 2000 })],
  handleValidation,
  asyncHandler(async (req, res) => {
    if (!req.file) throw new BadRequestError('No file provided (field name must be "file")');
    // V2.0-B (H4): the multer fileFilter only checked the client-supplied
    // Content-Type header, which is trivially spoofable. Now that the full
    // buffer is available, verify the actual bytes match what was declared
    // before persisting/encrypting it.
    if (!contentMatchesDeclaredType(req.file.buffer, req.file.mimetype)) {
      logAudit({ actorUserId: req.user.id, action: 'document.upload_rejected_signature_mismatch', ip: req.ip, metadata: { declaredMimeType: req.file.mimetype } });
      throw new BadRequestError('File content does not match its declared type');
    }
    const fileContext = ownerContext('documents', 'file', req.user.id);
    const saved = storage.save(req.file.buffer, fileContext);

    const info = db.prepare(
      `INSERT INTO documents
        (owner_id, original_filename_encrypted, stored_filename, mime_type, size_bytes, description_encrypted, file_iv, file_auth_tag, enc_format, checksum_sha256)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      req.user.id,
      encryptField(req.file.originalname, ownerContext('documents', 'original_filename_encrypted', req.user.id)),
      saved.storedFilename,
      req.file.mimetype,
      saved.sizeBytes,
      req.body.description ? encryptField(req.body.description, ownerContext('documents', 'description_encrypted', req.user.id)) : null,
      saved.iv,
      saved.authTag,
      saved.format,
      saved.checksum
    );

    logAudit({ actorUserId: req.user.id, action: 'document.uploaded', targetType: 'document', targetId: info.lastInsertRowid, ip: req.ip, metadata: { mimeType: req.file.mimetype, sizeBytes: saved.sizeBytes } });
    res.status(201).json({ document: toDTO(db.prepare('SELECT * FROM documents WHERE id = ?').get(info.lastInsertRowid)) });
  })
);

router.get(
  '/:id/download',
  requireOwnership((req) => db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id), 'document'),
  asyncHandler(async (req, res) => {
    const row = req.resource;
    const plaintext = storage.read(row.stored_filename, row.file_iv, row.file_auth_tag, row.checksum_sha256, row.enc_format, ownerContext('documents', 'file', row.owner_id));
    logAudit({ actorUserId: req.user.id, action: 'document.downloaded', targetType: 'document', targetId: row.id, ip: req.ip });
    res.setHeader('Content-Type', row.mime_type);
    res.setHeader('Content-Disposition', `attachment; filename="${decryptField(row.original_filename_encrypted, ownerContext('documents', 'original_filename_encrypted', row.owner_id)).replace(/"/g, '')}"`);
    res.send(plaintext);
  })
);

router.delete(
  '/:id',
  requireOwnership((req) => db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id), 'document'),
  asyncHandler(async (req, res) => {
    storage.remove(req.resource.stored_filename);
    db.prepare('DELETE FROM documents WHERE id = ?').run(req.params.id);
    logAudit({ actorUserId: req.user.id, action: 'document.deleted', targetType: 'document', targetId: Number(req.params.id), ip: req.ip });
    res.status(204).end();
  })
);

module.exports = router;
