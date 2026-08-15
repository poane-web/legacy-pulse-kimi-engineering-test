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
  fs.writeFileSync(path.join(config.uploadsDir, storedFilename), ciphertext);
  return { storedFilename, iv, authTag, checksum, sizeBytes: buffer.length };
}

/** Reads and decrypts a stored file, verifying against the stored checksum. */
function read(storedFilename, iv, authTag, expectedChecksum) {
  const ciphertext = fs.readFileSync(path.join(config.uploadsDir, storedFilename));
  const plaintext = decryptBuffer(ciphertext, iv, authTag);
  if (expectedChecksum && sha256Hex(plaintext) !== expectedChecksum) {
    throw new Error('File integrity check failed: checksum mismatch after decryption');
  }
  return plaintext;
}

function remove(storedFilename) {
  const p = path.join(config.uploadsDir, storedFilename);
  if (fs.existsSync(p)) fs.unlinkSync(p);
}

module.exports = { save, read, remove };
