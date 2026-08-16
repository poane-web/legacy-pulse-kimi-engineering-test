// Field-level and file encryption/decryption.
//
// Algorithm: AES-256-GCM (authenticated encryption -- protects both
// confidentiality and integrity; a tampered ciphertext fails to decrypt
// rather than silently returning corrupted plaintext).
//
// Key source: config.dataEncryptionKey (32 raw bytes, base64-encoded in the
// environment). This is the ONE symmetric key used for all field/file
// encryption in the MVP (see docs/V2_SECURITY_AUDIT.md / docs/THREAT_MODEL.md
// for the documented residual risk of not using a KMS / envelope encryption
// / per-tenant keys -- still true, still deferred to V2.0-F).
//
// ---------------------------------------------------------------------
// V2.0-C KEY MANAGEMENT CHANGE (docs/V2_0_C_PLAN.md §1, audit finding M1):
//
// V1 ciphertexts authenticated only the plaintext bytes -- nothing tied a
// ciphertext to which row/owner it belonged to. A blob copied into a
// different row of the same shape would still decrypt "successfully".
//
// This module now supports a VERSIONED format:
//   - legacy / v1:  "iv:authTag:ciphertext"           (unchanged, no AAD)
//   - new    / v2:  "v2:iv:authTag:ciphertext"         (AAD-bound)
//
// decryptField/decryptBuffer auto-detect which format a value is in by its
// prefix, so EVERY existing V1 ciphertext in the database continues to
// decrypt exactly as before -- no migration, no re-encryption, no
// behavior change for data already at rest. This is a deliberate,
// additive-only change; see docs/V2_0_C_PLAN.md for why (avoiding a
// flag-day re-encryption of the whole database is itself a security
// property -- it avoids a window where plaintext must be held in memory
// for the entire dataset at once).
//
// New callers should pass a `context` string (bound as GCM Additional
// Authenticated Data) identifying what the ciphertext belongs to -- see
// each route for the exact context string used. Decryption of a v2 value
// REQUIRES the same context string, or it fails closed (GCM auth tag
// mismatch), even with the correct key. Context granularity is
// owner-scoped (e.g. "memories.content:owner:42"), not row-scoped -- see
// docs/V2_0_C_PLAN.md §1 for why that's the deliberate, proportional
// choice for this MVP.
// ---------------------------------------------------------------------
'use strict';

const crypto = require('crypto');
const config = require('../config/env');

const ALGO = 'aes-256-gcm';
const key = Buffer.from(config.dataEncryptionKey, 'base64');
const V2_PREFIX = 'v2:';

/**
 * Encrypts a UTF-8 string field.
 * @param {string} plaintext
 * @param {string} [context] - if provided, binds this string as AAD and
 *   uses the new v2 format. If omitted, uses the legacy v1 format (no AAD)
 *   for backward compatibility with call sites not yet migrated.
 */
function encryptField(plaintext, context) {
  if (plaintext === null || plaintext === undefined) return null;
  const iv = crypto.randomBytes(12); // 96-bit IV, recommended for GCM
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  if (context) cipher.setAAD(Buffer.from(context, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const packed = [iv.toString('base64'), authTag.toString('base64'), ciphertext.toString('base64')].join(':');
  return context ? V2_PREFIX + packed : packed;
}

/**
 * Decrypts a value produced by encryptField. Throws if the auth tag does
 * not match (tampered/corrupted data, OR a wrong/missing context for a v2
 * value) rather than returning bad plaintext.
 * @param {string} packed
 * @param {string} [context] - required if `packed` is a v2-format value;
 *   must exactly match what was passed to encryptField at write time.
 */
function decryptField(packed, context) {
  if (packed === null || packed === undefined) return null;
  const raw = String(packed);
  const isV2 = raw.startsWith(V2_PREFIX);
  const body = isV2 ? raw.slice(V2_PREFIX.length) : raw;

  const [ivB64, tagB64, dataB64] = body.split(':');
  if (!ivB64 || !tagB64 || !dataB64) {
    throw new Error('Malformed encrypted field payload');
  }
  if (isV2 && !context) {
    throw new Error('Missing required AAD context to decrypt a v2 encrypted field');
  }
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(tagB64, 'base64');
  const ciphertext = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  if (isV2) decipher.setAAD(Buffer.from(context, 'utf8'));
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

/**
 * Encrypts a Buffer (uploaded file contents). Returns ciphertext buffer plus
 * the iv/authTag/format needed to decrypt, which callers persist in the DB
 * row alongside the file (not embedded in the file itself, so the on-disk
 * file alone is useless without the DB record).
 * @param {Buffer} buffer
 * @param {string} [context] - see encryptField.
 */
function encryptBuffer(buffer, context) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  if (context) cipher.setAAD(Buffer.from(context, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv: iv.toString('base64'), authTag: authTag.toString('base64'), format: context ? 'v2' : 'v1' };
}

/**
 * @param {Buffer} ciphertext
 * @param {string} ivB64
 * @param {string} authTagB64
 * @param {string} [context] - required if the value was encrypted with
 *   encryptBuffer's v2 format (see the `format` column persisted alongside).
 */
function decryptBuffer(ciphertext, ivB64, authTagB64, context) {
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  if (context) decipher.setAAD(Buffer.from(context, 'utf8'));
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = { encryptField, decryptField, encryptBuffer, decryptBuffer, sha256Hex, randomToken };
