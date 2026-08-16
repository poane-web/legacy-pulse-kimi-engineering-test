'use strict';

require('./testSetup');
const { encryptField, decryptField, encryptBuffer, decryptBuffer } = require('../utils/crypto');

// ---------------------------------------------------------------------
// M1 regression (docs/V2_SECURITY_AUDIT.md, Medium; docs/V2_0_C_PLAN.md
// §1): AES-256-GCM ciphertexts must now be bound to an owner context via
// AAD when a context is supplied, while legacy (no-context) V1 values
// continue to decrypt exactly as before.
// ---------------------------------------------------------------------
describe('V2.0-C / M1: AAD-bound versioned field encryption', () => {
  test('a v2 (context-bound) value round-trips correctly with the matching context', () => {
    const packed = encryptField('sensitive memory content', 'memories.content_encrypted:owner:42');
    expect(packed.startsWith('v2:')).toBe(true);
    expect(decryptField(packed, 'memories.content_encrypted:owner:42')).toBe('sensitive memory content');
  });

  test('decrypting a v2 value with the WRONG context fails closed (throws), even with the correct key', () => {
    const packed = encryptField('Alice\'s private memory', 'memories.content_encrypted:owner:1');
    expect(() => decryptField(packed, 'memories.content_encrypted:owner:2')).toThrow();
  });

  test('this defeats the confused-deputy attack: a ciphertext copied onto a DIFFERENT owner\'s row fails to decrypt', () => {
    // Simulates the exact attack class the audit finding describes: take a
    // legitimately-produced ciphertext for owner 1's data and imagine it
    // was substituted into a row belonging to owner 2 (e.g. via a bug
    // elsewhere, or direct DB tampering). Decrypting it AS owner 2's data
    // must fail, proving the ciphertext cannot be silently reinterpreted.
    const owner1Ciphertext = encryptField('Owner 1\'s will contents', 'documents.description_encrypted:owner:1');
    expect(() => decryptField(owner1Ciphertext, 'documents.description_encrypted:owner:2')).toThrow();
  });

  test('decrypting a v2 value with NO context at all throws a clear error', () => {
    const packed = encryptField('needs a context', 'memories.content_encrypted:owner:5');
    expect(() => decryptField(packed)).toThrow(/Missing required AAD context/);
  });

  test('a legacy v1 (no-context) value still decrypts correctly — zero migration required', () => {
    const legacyPacked = encryptField('old-style value, no context'); // no context arg -> v1 format
    expect(legacyPacked.startsWith('v2:')).toBe(false);
    expect(decryptField(legacyPacked)).toBe('old-style value, no context');
  });

  test('a legacy v1 value ignores a context argument if one happens to be passed (does not require it)', () => {
    const legacyPacked = encryptField('old value');
    expect(decryptField(legacyPacked, 'some.context:owner:1')).toBe('old value');
  });

  test('tampering with a v2 ciphertext still fails (integrity guarantee preserved)', () => {
    const packed = encryptField('integrity check', 'memories.content_encrypted:owner:7');
    const [prefix, iv, tag, data] = packed.split(':');
    const tamperedBuf = Buffer.from(data, 'base64');
    tamperedBuf[0] ^= 0xff;
    const tampered = [prefix, iv, tag, tamperedBuf.toString('base64')].join(':');
    expect(() => decryptField(tampered, 'memories.content_encrypted:owner:7')).toThrow();
  });
});

describe('V2.0-C / M1: AAD-bound versioned file (buffer) encryption', () => {
  test('a context-bound buffer round-trips with the matching context', () => {
    const original = Buffer.from('a real uploaded file\'s bytes');
    const { ciphertext, iv, authTag, format } = encryptBuffer(original, 'documents.file:owner:10');
    expect(format).toBe('v2');
    const decrypted = decryptBuffer(ciphertext, iv, authTag, 'documents.file:owner:10');
    expect(decrypted.equals(original)).toBe(true);
  });

  test('decrypting a context-bound buffer with the wrong context fails', () => {
    const original = Buffer.from('owner 10\'s document bytes');
    const { ciphertext, iv, authTag } = encryptBuffer(original, 'documents.file:owner:10');
    expect(() => decryptBuffer(ciphertext, iv, authTag, 'documents.file:owner:99')).toThrow();
  });

  test('a legacy (no-context) buffer still round-trips with format v1', () => {
    const original = Buffer.from('legacy file bytes');
    const { ciphertext, iv, authTag, format } = encryptBuffer(original);
    expect(format).toBe('v1');
    const decrypted = decryptBuffer(ciphertext, iv, authTag);
    expect(decrypted.equals(original)).toBe(true);
  });
});
