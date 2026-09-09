# V3-PG Checkpoint 02 — Step 2 complete

**Commit:** `e35a99a`
**Pushed:** yes, verified on `origin/security/v2-nodejs-track`

## What this step did
- Rebuilt `backend/src/db/postgres/schema.pg.sql` (reviewed, not
  mechanically translated) and applied it to the live PostgreSQL 16.15
  instance.
- Rebuilt the 15-test compatibility suite
  (`adapterCompatibility.test.js`) covering SELECT/INSERT/UPDATE/DELETE,
  generated IDs, affected-row counts, NULLs, booleans, timestamp
  formatting, CHECK/UNIQUE/FK constraint violations, named parameters,
  and transaction commit/rollback.

## Evidence
- **VERIFIED — database invariant only**: all 15 compatibility tests
  passing against the real, running PostgreSQL server (not SQLite, not
  mocked).
- **VERIFIED (regression)**: full existing SQLite suite, 142/142 passing,
  zero regressions.
- Confirmed tests correctly report "skipped" (not "passed") when
  PGHOST/PGUSER/PGPASSWORD/PGDATABASE are unset.
- **NOT YET TESTED**: real application route/service code against
  Postgres (Steps 3, 4, 6 still ahead).

## Environment note for recovery
Same PostgreSQL role/database as Checkpoint 01
(`/home/claude/.pg_test_credentials`). Schema now applied — if the
sandbox resets again, re-run `psql -f src/db/postgres/schema.pg.sql`
after recreating the role/database, before re-running this step's tests.
