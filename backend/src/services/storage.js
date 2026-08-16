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
 *
 * V2.0-C (docs/V2_0_C_PLAN.md §1): accepts an optional AAD `context`
 * string, binding the encrypted file to (typically) its owning user, so a
 * ciphertext blob copied onto another owner's row fails to decrypt. Callers
 * must persist the returned `format` alongside the other metadata and pass
 * the SAME context back into `read()`.
 */
function save(buffer, context) {
  const storedFilename = crypto.randomUUID();
  const { ciphertext, iv, authTag, format } = encryptBuffer(buffer, context);
  const checksum = sha256Hex(buffer);
  fs.writeFileSync(path.join(config.uploadsDir, storedFilename), ciphertext);
  return { storedFilename, iv, authTag, checksum, sizeBytes: buffer.length, format };
}

/**
 * Reads and decrypts a stored file, verifying against the stored checksum.
 * @param {string} context - required if the file was saved with `format ===
 *   'v2'`; must match what was passed to `save()`.
 */
function read(storedFilename, iv, authTag, expectedChecksum, format, context) {
  const ciphertext = fs.readFileSync(path.join(config.uploadsDir, storedFilename));
  const plaintext = decryptBuffer(ciphertext, iv, authTag, format === 'v2' ? context : undefined);
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
