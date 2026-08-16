// TOTP (Time-based One-Time Password), RFC 6238, built on HOTP (RFC 4226).
// Zero new npm dependencies, per the V2 constraint on not introducing
// unnecessary dependencies -- this is ~80 lines on top of Node's built-in
// `crypto` module, which is all the algorithm actually requires.
//
// V2.0-C (docs/V2_0_C_PLAN.md §3, audit finding L3): the users table has
// carried mfa_enabled / mfa_secret_encrypted columns since V1 with no code
// path using them. This module is the cryptographic core of the MFA
// feature wired into security.routes.js and auth.routes.js.
'use strict';

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const SECRET_BYTES = 20; // 160 bits, matches typical authenticator-app expectations
const STEP_SECONDS = 30;
const DIGITS = 6;

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    output += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder !== 0) {
    const lastChunk = bits.slice(bits.length - remainder).padEnd(5, '0');
    output += BASE32_ALPHABET[parseInt(lastChunk, 2)];
  }
  return output;
}

function base32Decode(encoded) {
  const clean = encoded.toUpperCase().replace(/=+$/, '');
  let bits = '';
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Invalid base32 character in TOTP secret');
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/** Generates a new random base32-encoded secret for a user to enroll. */
function generateSecret() {
  return base32Encode(crypto.randomBytes(SECRET_BYTES));
}

/** Builds an otpauth:// URI an authenticator app can scan/import. */
function provisioningUri(secretBase32, accountLabel, issuer = 'Legacy Pulse') {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function hotp(secretBase32, counter) {
  const key = base32Decode(secretBase32);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binCode % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * Verifies a submitted code against the current time step, allowing a
 * small window (default ±1 step = ±30s) to tolerate clock drift between
 * the server and the user's device -- standard TOTP practice.
 */
function verifyTotp(secretBase32, token, window = 1) {
  if (!/^\d{6}$/.test(String(token || ''))) return false;
  const currentStep = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    if (hotp(secretBase32, currentStep + errorWindow) === String(token)) return true;
  }
  return false;
}

module.exports = { generateSecret, provisioningUri, verifyTotp };
