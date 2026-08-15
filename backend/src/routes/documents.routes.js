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
const storage = require('../services/storage');
const { matchesDeclaredMime } = require('../utils/fileType');
const { BadRequestError } = require('../utils/errors');

const router = express.Router(); router.use(requireAuth);
const ALLOWED_DOCUMENT_MIME_TYPES = new Set(['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','text/plain','image/png','image/jpeg']);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: config.maxUploadMb * 1024 * 1024 }, fileFilter: (req,file,cb) => ALLOWED_DOCUMENT_MIME_TYPES.has(file.mimetype) ? cb(null,true) : cb(new BadRequestError(`File type ${file.mimetype} is not allowed`)) });
function toDTO(row) { return { id: row.id, filename: decryptField(row.original_filename_encrypted), mimeType: row.mime_type, sizeBytes: row.size_bytes, description: row.description_encrypted ? decryptField(row.description_encrypted) : null, createdAt: row.created_at }; }

router.get('/', asyncHandler(async (req,res) => { const rows=db.prepare('SELECT * FROM documents WHERE owner_id = ? ORDER BY created_at DESC').all(req.user.id); res.json({documents:rows.map(toDTO)}); }));
router.post('/', upload.single('file'), [body('description').optional().isString().isLength({max:2000})], handleValidation, asyncHandler(async(req,res)=>{
  if(!req.file) throw new BadRequestError('No file provided (field name must be "file")');
  if(!matchesDeclaredMime(req.file.buffer, req.file.mimetype)) throw new BadRequestError('File content does not match the declared file type');

  // Persist the encrypted blob first, but treat the DB insert as a transaction
  // boundary: if persistence fails, remove the orphaned blob immediately.
  const saved=storage.save(req.file.buffer);
  try {
    const info=db.prepare(`INSERT INTO documents (owner_id, original_filename_encrypted, stored_filename, mime_type, size_bytes, description_encrypted, file_iv, file_auth_tag, checksum_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(req.user.id,encryptField(req.file.originalname),saved.storedFilename,req.file.mimetype,saved.sizeBytes,req.body.description?encryptField(req.body.description):null,saved.iv,saved.authTag,saved.checksum);
    logAudit({actorUserId:req.user.id,action:'document.uploaded',targetType:'document',targetId:info.lastInsertRowid,ip:req.ip,metadata:{mimeType:req.file.mimetype,sizeBytes:saved.sizeBytes}});
    res.status(201).json({document:toDTO(db.prepare('SELECT * FROM documents WHERE id = ?').get(info.lastInsertRowid))});
  } catch (err) {
    try { storage.remove(saved.storedFilename); } catch (_) { /* preserve the original DB error */ }
    throw err;
  }
}));
router.get('/:id/download', requireOwnership(req=>db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id),'document'), asyncHandler(async(req,res)=>{
  const row=req.resource; const plaintext=storage.read(row.stored_filename,row.file_iv,row.file_auth_tag,row.checksum_sha256); logAudit({actorUserId:req.user.id,action:'document.downloaded',targetType:'document',targetId:row.id,ip:req.ip});
  const filename=decryptField(row.original_filename_encrypted).replace(/["\r\n\\/]/g,''); res.setHeader('Content-Type',row.mime_type); res.setHeader('Content-Disposition',`attachment; filename="${filename}"`); res.send(plaintext);
}));
router.delete('/:id', requireOwnership(req=>db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id),'document'), asyncHandler(async(req,res)=>{ storage.remove(req.resource.stored_filename); db.prepare('DELETE FROM documents WHERE id = ?').run(req.params.id); logAudit({actorUserId:req.user.id,action:'document.deleted',targetType:'document',targetId:Number(req.params.id),ip:req.ip}); res.status(204).end(); }));
module.exports=router;
