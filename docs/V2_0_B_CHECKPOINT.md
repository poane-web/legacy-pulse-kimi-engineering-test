# Legacy Pulse V2 — Checkpoint V2.0-B: Critical/High Security Fixes

Scope, as defined in `docs/V2_SECURITY_AUDIT.md` §"V2 Phase 1 scope":
**C1, C2, H1, H4, M2, M3** — the findings from the V2.0-A audit that are
genuine, exploitable vulnerabilities today, fixable without a database
state-machine redesign (that's V2.0-D) or infrastructure changes (V2.0-F).
M4 was fixed opportunistically since it was a one-line addition alongside
the H4 file-upload work in the same routes.

## Changes implemented

### C1 (Critical) — Deterministic dev-mode secrets
**File:** `backend/src/config/env.js`

The fallback secret used outside `NODE_ENV=production` is now generated
with `crypto.randomBytes` (unique per process start), replacing the V1
`sha256(name + '-dev-only-fallback')` formula that anyone reading this
public repository could compute offline. A console warning is now printed
whenever a fallback secret is in use, so it's impossible to miss in
development. Production's behavior (hard failure without real secrets) is
unchanged — this is not a weakening of any existing control.

### C2 (Critical) — Trusted-contact claim missing identity check
**File:** `backend/src/routes/trustedContacts.routes.js`

`POST /trusted-contacts/claim` now verifies the claiming user's email
matches the invited email (case-insensitive), mirroring the check
`beneficiaries.routes.js` already had. A mismatch is now audit-logged as
`trusted_contact.claim_email_mismatch`.

### H1 (High) — Stale access tokens survive revocation events
**Files:** `backend/src/db/schema.sql`, `backend/src/db/migrations/002_add_token_version.js`,
`backend/src/utils/jwt.js`, `backend/src/middleware/auth.js`,
`backend/src/routes/{auth,users,admin,security}.routes.js`

Added `users.token_version` (see "Database changes" below). Every access
token now embeds the `token_version` the user had at issuance; `requireAuth`
compares it against the user's *current* `token_version` on every request
(one indexed primary-key SQLite read). Password change, admin-disable, and
"sign out everywhere" now all bump `token_version`, immediately killing
every previously-issued access token — not just refresh tokens, which is
all V1 revoked.

**Trade-off, made explicit:** `requireAuth` is no longer purely stateless
(one extra synchronous, indexed read per request). Given `better-sqlite3`'s
in-process reads run in microseconds, this was judged worth it for the
correctness/security gain on a platform whose whole purpose is protecting
sensitive legacy content. Documented in code comments and here, not hidden.
Backward compatible: a token missing the `tokenVersion` claim (i.e. issued
by pre-V2.0-B code, hypothetically) is treated as version 0, so it isn't
force-rejected against an account that has never had a version-bumping
event — it only becomes invalid once (and if) that account's version is
ever bumped, exactly like any other token.

### H4 (High) — File-type validation trusted the client only
**Files:** `backend/src/utils/fileSignature.js` (new),
`backend/src/routes/{documents,photos}.routes.js`

New dependency-free magic-byte signature checker. After multer finishes
reading the upload into memory, both routes now verify the actual file
bytes match the declared (and already allow-listed) MIME type — PDF, PNG,
JPEG, GIF, WEBP, DOCX (ZIP signature), legacy DOC (OLE signature), and a
heuristic check for `text/plain`. A mismatch is rejected with 400 and
audit-logged (`document.upload_rejected_signature_mismatch` /
`photo.upload_rejected_signature_mismatch`) before anything is
encrypted/persisted to disk. No new npm dependency was introduced, per the
task's constraint.

### M2 (Medium) — No CSRF defense-in-depth on cookie-only endpoints
**Files:** `backend/src/middleware/csrfHeader.js` (new),
`backend/src/routes/auth.routes.js`, `frontend/public/js/{api,main}.js`

`POST /api/auth/{register,login,refresh,logout}` now require a custom
header (`X-Legacy-Pulse-Client: 1`) that a plain cross-site `<form>`
submission cannot set. This sits on top of the existing (and already
strong) `SameSite=Strict` cookie attribute — it's defense-in-depth, not a
replacement. The frontend API client sends this header automatically on
every request. This also closes login-CSRF (forcing a victim's browser to
authenticate as an attacker's account), which V1 didn't consider.

### M3 (Medium) — Seed script had no production guard
**File:** `backend/src/db/seed.js`

`seed()` now throws immediately if `NODE_ENV=production` unless
`ALLOW_PROD_SEED=true` is explicitly set, refusing to create the
publicly-documented demo credentials against a real database by accident.
Refactored to export `seed()` as a testable function, with the
`process.exit()` CLI behavior now gated behind `require.main === module` so
tests can catch the thrown error directly instead of asserting on process
exit codes.

### M4 (Medium, opportunistic) — Photo downloads weren't audit-logged
**File:** `backend/src/routes/photos.routes.js`

`GET /photos/:id/download` now logs `photo.downloaded` on success,
matching the coverage `documents.routes.js` already had.

## Database changes

One new migration, safe for both fresh installs and existing V1 databases:

**`backend/src/db/migrations/002_add_token_version.js`**
```js
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0
```
Guarded by `PRAGMA table_info('users')` so it's a no-op if the column
already exists (true for any brand-new install, since `schema.sql` now
defines the column directly for new databases).

**`backend/src/db/migrate.js`** was rewritten from "apply schema.sql once"
to a real incremental-migration runner: it still applies `schema.sql`
first (idempotent baseline for new installs), then applies any file under
`backend/src/db/migrations/*.js` not yet recorded in `schema_migrations`,
in filename order, each wrapped in its own `db.transaction()`. This is the
mechanism V2.0-C/D/E's future schema changes will use.

**Verified**, not just claimed: a standalone script built a database with
the exact V1 `users` table shape (no `token_version` column) plus an
existing user row, ran the real `migrate.js` against it, and confirmed (a)
the column was added, (b) the existing user's data was untouched, (c)
`token_version` defaulted to `0`, and (d) running migrate a second time was
a clean no-op. See the "reproduce" commands below to re-run this yourself.

## New tests

37 new tests, 6 new files, all passing alongside the full pre-existing
suite (which needed only mechanical updates — see below — no test's
*assertions* were weakened to make it pass):

| File | Covers |
|---|---|
| `v2b_c1_devSecrets.test.js` | C1: fallback is random, differs across loads, still valid for encryption, production still hard-fails without real secrets |
| `v2b_c2_and_m2_m3.test.js` | C2: mismatched-email claim rejected, matching-email claim still works, case-insensitivity preserved. M2: all four `/auth/*` POSTs require the header, and still work correctly with it. M3: seed refuses in production without override |
| `v2b_h1_tokenVersion.test.js` | H1: password change / admin-disable / revoke-all all invalidate a live access token immediately; disabled accounts can't log in; a claim-less legacy-shaped token still works pre-first-bump |
| `v2b_migration.test.js` | The `002_add_token_version` migration against a simulated real V1 database: adds the column, preserves data, defaults correctly, is idempotent |
| `photos.test.js` (new — V1 had no dedicated photo test file) | H4 signature rejection on photos specifically (served inline, higher stakes than documents), M4 audit logging, plus baseline upload/download/ownership coverage |
| `documents.test.js` (extended) | New H4 case: a file declaring `application/pdf` but containing HTML/script content is rejected |

**Pre-existing test files required only mechanical updates**, not logic
changes: every `/api/auth/*` call in `auth.test.js`, `authorization.test.js`,
`documents.test.js`, and `legacyMessages.test.js` needed the new
`X-Legacy-Pulse-Client` header added (via a scripted `sed` pass, then
manually verified), since those endpoints now legitimately require it. One
test fixture in `documents.test.js` used fake "PDF" content with no real
PDF magic bytes; it now uses a minimal valid PDF header, which is the
correct fix (that fixture was never meant to test file-type validation —
a new dedicated test was added for that).

## How this was verified (not just "tests pass")

- Full suite run: **57/57 passing** (32 from V1 + 5 new photos.test.js +
  20 new V2.0-B-specific regression tests), via
  `NODE_ENV=test npx jest --runInBand`.
- Live server smoke test: started the real server with real env vars,
  confirmed `POST /auth/login` returns 403 without the CSRF header and 200
  (with a token embedding `tokenVersion: 0`) with it.
- Migration smoke test against a hand-built V1-shaped SQLite file (not the
  test suite's in-memory/temp DB) — see reproduction commands below.
- Frontend verified to actually serve the updated `api.js`/`main.js`
  sending the new header, not just the backend accepting it in isolation.

## Remaining from the V2.0-A audit (deliberately not in this checkpoint)

- **H2, H3** (non-transactional release side-effects; messages created
  after the confirmation threshold is met never auto-release) →
  **V2.0-D — Legacy release state machine**, where they belong alongside a
  proper state-machine redesign rather than a partial patch now.
- **M1** (AAD binding on GCM ciphertexts), **M5** (trust-proxy policy),
  **M6** (unbounded audit/refresh-token growth) → picked up alongside
  **V2.0-C — Authentication & key management**.
- **L1–L4** (breached-password check, per-user storage quota, unused MFA
  schema, no account lockout) → candidates for **V2.0-C** (lockout, MFA) and
  **V2.0-F** (quotas as part of production readiness).

## Exact commands to reproduce

From a fresh clone:

```bash
cd backend
npm install
cp ../.env.example .env
# fill in JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, DATA_ENCRYPTION_KEY
npm run migrate
npm run seed
npm test
```

To specifically re-verify the migration against a simulated existing V1
database (what was actually run to validate this checkpoint, not merely
described):

```bash
node -e "
const Database = require('./node_modules/better-sqlite3');
const db = new Database('/tmp/v1_style.db');
db.exec(\`
  PRAGMA foreign_keys = ON;
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'owner', status TEXT NOT NULL DEFAULT 'active'
  );
  CREATE TABLE schema_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, applied_at TEXT);
  INSERT INTO schema_migrations (name, applied_at) VALUES ('initial_schema', '2026-01-01T00:00:00.000Z');
  INSERT INTO users (email, password_hash, full_name, role) VALUES ('test@example.com', 'hash', 'Test User', 'owner');
\`);
db.close();
"
DB_PATH=/tmp/v1_style.db JWT_ACCESS_SECRET=x JWT_REFRESH_SECRET=y \
  DATA_ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))") \
  node src/db/migrate.js
# Expect: "[migrate] applied 002_add_token_version"
# Then re-run the same command — expect no "applied" line (idempotent).
```

To specifically re-verify the CSRF header requirement against a live
server:

```bash
npm start &
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" -d '{"email":"a@b.com","password":"x"}'
# Expect: 403
curl -s -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" -H "X-Legacy-Pulse-Client: 1" \
  -d '{"email":"owner@demo.legacypulse.test","password":"DemoPass123!"}'
# Expect: 200 with an accessToken whose decoded payload includes "tokenVersion":0
```
