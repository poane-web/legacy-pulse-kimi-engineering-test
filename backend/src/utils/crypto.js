// Field-level and file encryption/decryption.
//
// Algorithm: AES-256-GCM (authenticated encryption — protects both
// confidentiality and integrity; a tampered ciphertext fails to decrypt
// rather than silently returning corrupted plaintext).
//
// Key source: config.dataEncryptionKey (32 raw bytes, base64-encoded in the
// environment). This is the ONE symmetric key used for all field/file
// encryption in the MVP (see docs/THREAT_MODEL.md for the documented
// residual risk of not using a KMS / envelope encryption / per-tenant keys).
'use strict';

const crypto = require('crypto');
const config = require('../config/env');

const ALGO = 'aes-256-gcm';
const key = Buffer.from(config.dataEncryptionKey, 'base64');

/**
 * Encrypts a UTF-8 string field. Returns a single string of the form
 * "iv:authTag:ciphertext" (all base64), so a single TEXT column stores
 * everything needed to decrypt without other state.
 */
function encryptField(plaintext) {
  if (plaintext === null || plaintext === undefined) return null;
  const iv = crypto.randomBytes(12); // 96-bit IV, recommended for GCM
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv.toString('base64'), authTag.toString('base64'), ciphertext.toString('base64')].join(':');
}

/**
 * Decrypts a value produced by encryptField. Throws if the auth tag does
 * not match (tampered/corrupted data) rather than returning bad plaintext.
 */
function decryptField(packed) {
  if (packed === null || packed === undefined) return null;
  const [ivB64, tagB64, dataB64] = String(packed).split(':');
  if (!ivB64 || !tagB64 || !dataB64) {
    throw new Error('Malformed encrypted field payload');
  }
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(tagB64, 'base64');
  const ciphertext = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

/**
 * Encrypts a Buffer (uploaded file contents). Returns ciphertext buffer plus
 * the iv/authTag needed to decrypt, which callers persist in the DB row
 * alongside the file (not embedded in the file itself, so the on-disk file
 * alone is useless without the DB record).
 */
function encryptBuffer(buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv: iv.toString('base64'), authTag: authTag.toString('base64') };
}

function decryptBuffer(ciphertext, ivB64, authTagB64) {
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
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
