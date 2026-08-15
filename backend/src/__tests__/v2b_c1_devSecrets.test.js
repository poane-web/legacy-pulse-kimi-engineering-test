'use strict';

// This file deliberately does NOT require testSetup.js: it needs to
// control NODE_ENV and the presence/absence of secret env vars itself,
// which testSetup.js already sets. It uses jest.resetModules() to force
// fresh evaluation of config/env.js under each scenario, so it's kept in
// its own file to avoid contaminating other test files' module cache.
const crypto = require('crypto');

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

// ---------------------------------------------------------------------
// C1 regression (docs/V2_SECURITY_AUDIT.md, Critical): V1's dev-mode
// fallback secret was sha256("<VAR_NAME>-dev-only-fallback") — a value
// computable by anyone who has read this public repository's source. It
// must now be random and unique per process, never derivable from source.
// ---------------------------------------------------------------------
describe('V2.0-B / C1: dev-mode secret fallback is not derivable from source', () => {
  test('the fallback is not the old deterministic sha256(name + suffix) value', () => {
    delete process.env.JWT_ACCESS_SECRET;
    delete process.env.JWT_REFRESH_SECRET;
    delete process.env.DATA_ENCRYPTION_KEY;
    process.env.NODE_ENV = 'development';

    jest.resetModules();
    // eslint-disable-next-line global-require
    const config = require('../config/env');

    const oldDeterministicValue = crypto.createHash('sha256').update('JWT_ACCESS_SECRET-dev-only-fallback').digest('hex');
    expect(config.jwtAccessSecret).not.toBe(oldDeterministicValue);

    const oldDeterministicKey = crypto.createHash('sha256').update('DATA_ENCRYPTION_KEY-dev-only-fallback').digest('base64');
    expect(config.dataEncryptionKey).not.toBe(oldDeterministicKey);
  });

  test('two separate process-local loads with no secrets set produce DIFFERENT values (proves randomness, not a fixed formula)', () => {
    delete process.env.JWT_ACCESS_SECRET;
    delete process.env.JWT_REFRESH_SECRET;
    delete process.env.DATA_ENCRYPTION_KEY;
    process.env.NODE_ENV = 'development';

    jest.resetModules();
    // eslint-disable-next-line global-require
    const configA = require('../config/env');
    jest.resetModules();
    // eslint-disable-next-line global-require
    const configB = require('../config/env');

    expect(configA.jwtAccessSecret).not.toBe(configB.jwtAccessSecret);
    expect(configA.jwtRefreshSecret).not.toBe(configB.jwtRefreshSecret);
    expect(configA.dataEncryptionKey).not.toBe(configB.dataEncryptionKey);
  });

  test('the fallback DATA_ENCRYPTION_KEY is still valid (32 bytes base64) so encryption keeps working in dev', () => {
    delete process.env.DATA_ENCRYPTION_KEY;
    process.env.JWT_ACCESS_SECRET = 'x';
    process.env.JWT_REFRESH_SECRET = 'y';
    process.env.NODE_ENV = 'development';

    jest.resetModules();
    // eslint-disable-next-line global-require
    const config = require('../config/env');
    expect(Buffer.from(config.dataEncryptionKey, 'base64').length).toBe(32);
  });

  test('production still refuses to start without real secrets (unchanged guarantee from V1)', () => {
    delete process.env.JWT_ACCESS_SECRET;
    delete process.env.JWT_REFRESH_SECRET;
    delete process.env.DATA_ENCRYPTION_KEY;
    process.env.NODE_ENV = 'production';

    jest.resetModules();
    expect(() => require('../config/env')).toThrow(/Missing required environment variable/);
  });
});
