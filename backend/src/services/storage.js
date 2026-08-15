// File storage abstraction.
//
// Architectural seam: routes call `storage.save()` / `storage.read()` /
// `storage.remove()` rather than touching `fs` directly. The MVP
// implementation writes AES-256-GCM-encrypted bytes to a local directory
// (`config.uploadsDir`). A production deployment would swap this module
// for one backed by S3/GCS (with either server-side or the same
// application-layer envelope encryption) without changing any route code.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config/env');
const { encryptBuffer, decryptBuffer, sha256Hex } = require('../utils/crypto');

if (!fs.existsSync(config.uploadsDir)) fs.mkdirSync(config.uploadsDir, { recursive: true });

// Stored names are generated internally and must never be treated as paths.
// Keep this invariant at the storage boundary as defense-in-depth in case a
// database row is ever corrupted or manipulated by a future code path.
const STORED_FILENAME_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function safeStoragePath(storedFilename) {
  if (typeof storedFilename !== 'string' || !STORED_FILENAME_RE.test(storedFilename)) {
    throw new Error('Invalid stored filename');
  }
  const root = path.resolve(config.uploadsDir);
  const candidate = path.resolve(root, storedFilename);
  if (candidate === root || !candidate.startsWith(`${root}${path.sep}`)) {
    throw new Error('Invalid storage path');
  }
  return candidate;
}

/**
 * Encrypts `buffer` and writes it to disk under a random filename (never
 * derived from the user-supplied original filename, which avoids path
 * traversal and avoids leaking content hints via directory listing).
 * Returns metadata to persist in the DB row.
 */
function save(buffer) {
  const storedFilename = crypto.randomUUID();
  const { ciphertext, iv, authTag } = encryptBuffer(buffer);
  const checksum = sha256Hex(buffer);
  fs.writeFileSync(safeStoragePath(storedFilename), ciphertext, { flag: 'wx', mode: 0o600 });
  return { storedFilename, iv, authTag, checksum, sizeBytes: buffer.length };
}

/** Reads and decrypts a stored file, verifying against the stored checksum. */
function read(storedFilename, iv, authTag, expectedChecksum) {
  const ciphertext = fs.readFileSync(safeStoragePath(storedFilename));
  const plaintext = decryptBuffer(ciphertext, iv, authTag);
  if (expectedChecksum && sha256Hex(plaintext) !== expectedChecksum) {
    throw new Error('File integrity check failed: checksum mismatch after decryption');
  }
  return plaintext;
}

function remove(storedFilename) {
  const p = safeStoragePath(storedFilename);
  if (fs.existsSync(p)) fs.unlinkSync(p);
}

module.exports = { save, read, remove, safeStoragePath };
