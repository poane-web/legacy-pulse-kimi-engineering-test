'use strict';

require('./testSetup');
const { encryptField, decryptField, encryptBuffer, decryptBuffer } = require('../utils/crypto');

describe('field encryption (AES-256-GCM)', () => {
  test('encrypts and decrypts round-trip correctly', () => {
    const plaintext = 'This is a secret memory about grandma.';
    const packed = encryptField(plaintext);
    expect(packed).not.toContain(plaintext);
    expect(decryptField(packed)).toBe(plaintext);
  });

  test('produces different ciphertext for the same plaintext each time (random IV)', () => {
    const a = encryptField('hello world');
    const b = encryptField('hello world');
    expect(a).not.toBe(b);
  });

  test('throws on tampered ciphertext instead of returning corrupted plaintext', () => {
    const packed = encryptField('sensitive instructions');
    const [iv, tag, data] = packed.split(':');
    const tamperedData = Buffer.from(data, 'base64');
    tamperedData[0] ^= 0xff;
    const tampered = [iv, tag, tamperedData.toString('base64')].join(':');
    expect(() => decryptField(tampered)).toThrow();
  });

  test('handles null gracefully', () => {
    expect(encryptField(null)).toBeNull();
    expect(decryptField(null)).toBeNull();
  });
});

describe('file encryption (AES-256-GCM buffers)', () => {
  test('encrypts and decrypts a buffer round-trip', () => {
    const original = Buffer.from('fake PDF bytes representing a will document');
    const { ciphertext, iv, authTag } = encryptBuffer(original);
    expect(ciphertext.equals(original)).toBe(false);
    const decrypted = decryptBuffer(ciphertext, iv, authTag);
    expect(decrypted.equals(original)).toBe(true);
  });

  test('fails to decrypt with the wrong auth tag', () => {
    const original = Buffer.from('some file content');
    const { ciphertext, iv } = encryptBuffer(original);
    const wrongTag = Buffer.alloc(16, 1).toString('base64');
    expect(() => decryptBuffer(ciphertext, iv, wrongTag)).toThrow();
  });
});
