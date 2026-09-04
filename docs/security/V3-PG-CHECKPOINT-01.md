# V3-PG Checkpoint 01 — Step 1 complete

**Commit:** `fd62ae5`
**Pushed:** yes, verified on `origin/security/v2-nodejs-track`
**Date context:** rebuild after a sandbox reset lost the original (unpushed) Steps 1-4

## What this step did
- Reinstalled PostgreSQL 16.15 natively (no Docker available), created a
  dedicated `legacy_pulse_test` role/database with a runtime-generated
  password (not committed anywhere).
- Rebuilt `backend/src/db/postgres/placeholderTranslator.js`: a real
  character-by-character SQL tokenizer translating SQLite's `?`/`@name`
  placeholders to Postgres's `$1..$n`, correctly ignoring `?`/`@` inside
  string literals, comments, and quoted identifiers.
- Rebuilt `backend/src/db/postgres/adapter.js`: wraps a real `pg` Pool
  with the same `prepare().get/all/run()` shape the app already uses.

## Evidence
- **VERIFIED — database invariant only**: 20/20 placeholder-translator
  adversarial unit tests passing (pure logic, no DB connection needed for
  this specific test file).
- **VERIFIED (regression)**: full existing SQLite suite, 142/142 passing,
  zero regressions — this step added no route/service changes.
- **NOT YET TESTED**: the adapter itself against a live Postgres
  connection (that's Step 2, next).

## Environment note for recovery
PostgreSQL role/database were recreated this session; credentials are
runtime-only (`/home/claude/.pg_test_credentials`, not committed, not
recoverable from git — must be regenerated again if the sandbox resets).
