// PostgreSQL adapter Step 1/2/3: presents the same application-facing
// operations the app already calls everywhere against better-sqlite3 --
// db.prepare(sql).get(...), .all(...), .run(...), plus db.transaction(fn)
// and db.exec(sql) -- but backed by a real `pg` Pool.
//
// DESIGN CONSTRAINT (explicit, from the task): do not rewrite business
// logic to accommodate Postgres. Every route/service file's actual SQL
// text and control flow stays unchanged; only `await` is added at call
// sites (see docs/security/V3-POSTGRESQL-VERIFICATION.md for the exact
// list of files touched and why each change is mechanical, not logical).
//
// ONE necessary, narrow exception to "don't touch business logic," and
// why: better-sqlite3 has exactly one connection, ever -- so
// db.transaction(fn) can simply run fn() between BEGIN/COMMIT on that
// single connection, and any db.prepare(...).run() call made from inside
// fn (referencing the module-level `db` via closure) automatically
// participates, because there's only one connection to participate on.
// A `pg` Pool has MANY connections; a transaction must pin ALL its
// queries to one checked-out client, or they don't actually share a
// transaction. So `db.transaction(fn)` here calls `fn(txDb)`, passing a
// transaction-scoped db handle bound to the checked-out client. The
// caller (services/legacyMessageRelease.js) accepts that argument and
// uses it instead of closing over the module-level `db` -- this changes
// HOW that function obtains its db reference, not what any SQL statement
// does, in what order, or under what conditions. Every statement,
// condition, and side effect is byte-for-byte the same.
'use strict';

const { Pool, types } = require('pg');
const { translatePlaceholders, resolveParams } = require('./placeholderTranslator');

// See schema.pg.sql's header comment for the full rationale: timestamptz
// columns are the correct type choice, but `pg` returns them as JS Date
// objects by default, which would silently change what every route
// receives compared to the SQLite path's plain ISO-8601 strings. These
// type parsers normalize BOTH timestamp OIDs to the exact same
// `...Z`-suffixed ISO-8601 string format `new Date().toISOString()`
// already produces elsewhere in this codebase, so no route/service code
// needs to know or care which driver is active.
const TIMESTAMPTZ_OID = 1184;
const TIMESTAMP_OID = 1114;
types.setTypeParser(TIMESTAMPTZ_OID, (val) => (val === null ? null : new Date(val).toISOString()));
types.setTypeParser(TIMESTAMP_OID, (val) => (val === null ? null : new Date(val).toISOString()));

function needsReturningId(translatedSql) {
  return /^\s*insert\s+into/i.test(translatedSql) && !/\breturning\b/i.test(translatedSql);
}

/**
 * Wraps a `pg` query-capable object (a Pool, or a checked-out Client
 * during a transaction) with the prepare().get/all/run() surface.
 */
function makeDbHandle(queryable) {
  function prepare(sql) {
    const { text: translated, paramNames } = translatePlaceholders(sql);
    const appendsReturningId = needsReturningId(translated);
    const execText = appendsReturningId ? `${translated} RETURNING id` : translated;

    return {
      async get(...args) {
        const params = resolveParams(paramNames, args);
        const result = await queryable.query(execText, params);
        return result.rows[0];
      },
      async all(...args) {
        const params = resolveParams(paramNames, args);
        const result = await queryable.query(execText, params);
        return result.rows;
      },
      async run(...args) {
        const params = resolveParams(paramNames, args);
        const result = await queryable.query(execText, params);
        return {
          changes: result.rowCount,
          lastInsertRowid: appendsReturningId && result.rows[0] ? result.rows[0].id : undefined,
        };
      },
    };
  }

  async function exec(sql) {
    await queryable.query(sql);
  }

  return { prepare, exec };
}

function createPostgresDb() {
  const pool = new Pool({
    host: process.env.PGHOST || '127.0.0.1',
    port: parseInt(process.env.PGPORT || '5432', 10),
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    max: parseInt(process.env.PG_POOL_MAX || '10', 10),
  });

  const base = makeDbHandle(pool);

  return {
    prepare: base.prepare,
    exec: base.exec,

    // Mirrors better-sqlite3's db.pragma() call sites in db/index.js
    // (journal_mode, foreign_keys) -- both are SQLite-specific concepts
    // with no Postgres equivalent needed (Postgres enforces FKs always;
    // there is no WAL pragma to set). No-op, not silently wrong: FK
    // enforcement is unconditional in Postgres, which is a STRICTER
    // guarantee than SQLite's opt-in pragma, never weaker.
    pragma() {},

    transaction(fn) {
      return async (...args) => {
        const client = await pool.connect();
        const txDb = makeDbHandle(client);
        try {
          await client.query('BEGIN');
          const result = await fn(txDb, ...args);
          await client.query('COMMIT');
          return result;
        } catch (err) {
          await client.query('ROLLBACK');
          throw err;
        } finally {
          client.release();
        }
      };
    },

    async close() {
      await pool.end();
    },

    name: `postgres://${process.env.PGHOST || '127.0.0.1'}/${process.env.PGDATABASE}`,

    // Exposed for tests/diagnostics that need to reach the underlying
    // pool directly (e.g. to open independent connections for
    // concurrency attacks) without reaching into module internals.
    _pool: pool,
  };
}

module.exports = { createPostgresDb, makeDbHandle, needsReturningId };
