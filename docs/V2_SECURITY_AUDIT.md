# Legacy Pulse V2 — Security & Architecture Audit (Checkpoint V2.0-A)

**Status: Audit only. No code changed in this checkpoint.**

Method: every route file, middleware, utility, service, and the DB schema
were read in full against the repository as pushed
(`be82c25`), not against the V1 threat model's claims. Each V1 threat-model
mitigation was re-tested by reading the actual code path, not assumed.
Findings below are new, concrete, code-level issues found during that
re-validation — this is not a restatement of `docs/THREAT_MODEL.md`.

Severity is assessed by **exploitability × impact** on this specific
application (a legacy/estate-content platform where confidentiality and
correct release timing are the core promises), not by generic CVSS.

---

## CRITICAL

### C1. Deterministic, source-derivable secrets outside `NODE_ENV=production`
**Where:** `backend/src/config/env.js`, `devFallback()`

If `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, or `DATA_ENCRYPTION_KEY` are
unset, the app silently falls back to `sha256("<VAR_NAME>-dev-only-fallback")`
— **unless** `NODE_ENV === 'production'` exactly. Because the source is
public (this repo), anyone can compute these fallback values offline. If
the app is ever run with `NODE_ENV` unset, `development`, `staging`, or any
value other than the literal string `production` — a startlingly common
real-world misconfiguration (forgotten env var, container base image
default, CI/staging environment accidentally reachable from the internet)
— an attacker can:
- Forge arbitrary JWT access tokens, including `role: "admin"`, for
  instant full account/privilege takeover with zero credentials.
- Derive `DATA_ENCRYPTION_KEY` and decrypt every encrypted field and file
  in the database/upload directory offline, given DB/file access (e.g. via
  a backup leak, SSRF, or any lesser bug that yields read access).

This single fallback undermines every other control in the system
(authorization, encryption architecture) the moment `NODE_ENV` isn't
exactly `production`. **This is the highest-priority fix in V2.**

### C2. Trusted-contact invite claiming has no identity/email verification
**Where:** `backend/src/routes/trustedContacts.routes.js`, `POST /claim`

Compare with `beneficiaries.routes.js` `POST /claim`, which checks
`row.email.toLowerCase() !== req.user.email.toLowerCase()`. The
trusted-contact claim route has **no equivalent check** — it only verifies
the raw token hashes to a pending invite. Any authenticated user who
obtains the raw invite token (leaked link, forwarded email, shoulder-surf,
intercepted message) can claim trusted-contact status under **any account
they control**, regardless of whether they are the person the Owner
intended. Trusted contacts are one half of the two-person release-trigger
rule (`docs/ARCHITECTURE.md` §6) — this bug means that control's integrity
depends entirely on token secrecy in transit, with no second factor at
claim time. Given the explicit purpose of the two-person rule is to resist
a *single* untrustworthy actor, this is a critical gap in exactly the
control meant to prevent that.

---

## HIGH

### H1. Disabling/changing a password does not invalidate already-issued access tokens
**Where:** `middleware/auth.js` (`requireAuth`), `users.routes.js`
(password change), `admin.routes.js` (`PUT /users/:id/status`)

`requireAuth` is pure JWT signature verification with no DB lookup — by
design, for statelessness. But neither "disable user" nor "change password"
have any mechanism to invalidate an access token already in a client's
hands; only refresh tokens are revoked. An attacker with a stolen access
token keeps full API access for up to its remaining TTL (≤15 min) **after**
an admin disables the account or the legitimate user changes their password
in direct response to a suspected compromise — precisely the moment
revocation matters most.

### H2. Release-side-effects are not transactional
**Where:** `trustedContacts.routes.js` (`POST /confirm/:ownerId`),
`services/releaseScheduler.js` (`runReleaseSweep`)

Confirmation insert → count → (conditionally) loop of message-release +
notification-insert are separate `better-sqlite3` statements with no
`db.transaction()` wrapper. A process crash/OOM/power-loss between
statements can leave: a confirmation recorded but no release triggered even
though the threshold was reached, or some messages released with others
left pending, or a released message with its notification never inserted.
For a system whose product promise is "your message reaches the right
person, once, reliably," this is a correctness/integrity defect with real
user impact, not just a style issue.

### H3. Legacy messages created after the confirmation threshold is already met never release
**Where:** `trustedContacts.routes.js` (`POST /confirm/:ownerId`)

The release sweep for `trusted_contact_confirmation` messages runs only at
the moment the Nth confirmation is submitted, scanning *currently pending*
messages. If confirmations are already at/above the threshold (e.g. the
Owner has passed away and it's already been confirmed) and the Owner's
account is later used to create a **new** message of this release type
(e.g. by a family member with access, or scheduled ahead of time before the
event), that message will sit in `pending` forever — there is no
re-evaluation on create, and no periodic sweep for this release type
(unlike `scheduled_date`, which the cron job re-scans every minute
regardless of creation time). This is a "beneficiary wrongly denied
access" bug — the inverse of an over-release bug, but still a
release-condition defect.

### H4. File-type validation trusts the client-supplied `Content-Type` only
**Where:** `documents.routes.js`, `photos.routes.js` (`multer` `fileFilter`)

`fileFilter` checks `file.mimetype`, which is the multipart
`Content-Type` field the **client** sets — trivially spoofable. No
magic-byte/content sniffing is performed. Impact is substantially reduced
by Helmet's `X-Content-Type-Options: nosniff` (present) and documents being
served `Content-Disposition: attachment` (present), but photos are served
**inline** with only the attacker-controlled stored MIME type as the
`Content-Type` response header — nosniff is the only backstop. This should
not be the only line of defense for a file-upload feature explicitly
called out as a required area of scrutiny.

---

## MEDIUM

### M1. AES-256-GCM ciphertexts have no Additional Authenticated Data (AAD) binding
**Where:** `utils/crypto.js` (`encryptField`, `encryptBuffer`)

GCM's authentication tag currently authenticates only the plaintext bytes,
not which row/column/owner the ciphertext belongs to. A ciphertext blob
copied verbatim into a different row of the same shape (via a future SQL
injection elsewhere, a buggy migration, or direct DB access) would still
decrypt "successfully" with no cryptographic signal that it's misplaced.
Binding AAD (e.g. `"table:column:id:owner_id"`) is a standard, cheap
hardening that turns this into a hard failure instead of a silent
mismatch.

### M2. No CSRF defense-in-depth on cookie-only endpoints
**Where:** `POST /api/auth/refresh`, `POST /api/auth/logout`

These two endpoints authenticate via the `httpOnly`/`SameSite=Strict`
refresh cookie alone (no bearer token required, by necessity — refresh
issues the *first* access token of a session). `SameSite=Strict` is a
strong primary defense, but it is not a CSRF token and has documented
edge-case gaps in some browser/navigation combinations. All other
state-changing routes require a bearer token an attacker's page can't
attach, so this is scoped narrowly, but a defense-in-depth check (e.g. a
custom header a simple cross-site form can't set) is cheap and closes the
gap entirely.

### M3. Seed script has no production guard
**Where:** `backend/src/db/seed.js`

`npm run seed` creates admin/owner/beneficiary accounts with the password
`DemoPass123!` — published in the public README and git history — against
whatever `DB_PATH` currently points to, with **no check** on `NODE_ENV`.
Running this against a real deployment's database by mistake creates a
publicly-known privileged credential.

### M4. Inconsistent audit coverage: photo downloads are not logged
**Where:** `photos.routes.js` (`GET /:id/download`)

`documents.routes.js` logs `document.downloaded` on every successful,
authorized download. The equivalent photo route does not log anything on
success (only `requireOwnership` logs unauthorized *attempts*). This is an
audit-completeness gap, not an access-control gap, but the product
explicitly promises an activity/audit log covering account activity.

### M5. `req.ip` used for rate limiting and audit logs with no explicit trust-proxy policy
**Where:** `app.js`

Express's default (`trust proxy` unset) is safe against IP spoofing, but
means that if this app is later deployed behind a reverse proxy/load
balancer without deliberately configuring `trust proxy`, every request will
appear to originate from the proxy's IP — collapsing per-client rate
limiting into one shared bucket and making audit-log IPs useless. This
needs an explicit, documented decision before any real deployment, not a
silent default.

### M6. Unbounded growth of `refresh_tokens` and `audit_logs`
**Where:** `db/schema.sql`

Expired/revoked refresh tokens and all audit log rows are retained forever
with no purge/archival job. Not an active vulnerability, but a
resource/performance concern that compounds over the life of a real
deployment (backup size, query latency, eventual disk exhaustion).

---

## LOW

### L1. No breached-password / stronger complexity check beyond length+letter+number
Already-documented policy (10+ chars, 1 letter, 1 number) is reasonable for
an MVP but doesn't check against known-breached password lists. bcrypt's
72-byte truncation is a non-issue at this password length (informational
only).

### L2. No per-user storage quota
Per-file size is capped (`MAX_UPLOAD_MB`), but there's no aggregate
per-owner storage ceiling — a single account can upload unboundedly many
files, risking disk exhaustion in a multi-tenant deployment.

### L3. MFA schema exists (`users.mfa_enabled`, `mfa_secret_encrypted`) but is fully unused
Already flagged as deferred in V1; re-confirmed unchanged.

### L4. No account lockout after repeated failed logins (rate limiting only)
Already flagged in V1 threat model as an accepted residual risk;
re-validated as still accurate and still unaddressed.

---

## Explicitly re-validated as still holding (no new issue, confirms V1 claim)

- Password hashing (bcrypt, cost 12), parameterized SQL everywhere (no
  injection points found), randomized on-disk filenames (no path
  traversal), `requireOwnership` correctly enforced on every
  single-resource route I checked (memories, timeline, documents, photos,
  legacy messages, beneficiaries, trusted contacts), admin routes never
  call `decryptField`/`decryptBuffer` (verified by grep — zero matches in
  `admin.routes.js`), refresh-token rotation-on-use is implemented
  correctly and verified in `auth.test.js`.

## Areas out of scope for V2 Phase 1 (flagged for later checkpoints per the plan)

- H2/H3 (transactional release integrity, missed-window release) →
  **V2.0-D — Legacy release state machine**
- Life-event/photo/memory data-model coupling and richer authorization
  nuance → **V2.0-E — Life-event architecture**
- KMS/envelope encryption, managed secrets, external object storage, MFA
  provider integration, monitoring/alerting, backups/DR, penetration
  testing → **V2.0-F — Production readiness** (these are infrastructure
  concerns no application-code change can fully satisfy — see that
  checkpoint's report for an explicit list)

---

## V2 Phase 1 scope (next checkpoint: V2.0-B)

Phase 1 (V2.0-B) will fix **C1, C2, H1, H4, M2, M3** — the
findings that are (a) genuine security vulnerabilities exploitable today,
not just architectural nice-to-haves, and (b) fixable without a database
migration or state-machine redesign. M1, M4, M5, M6 and the L-tier items
will be picked up alongside V2.0-C (key management) and V2.0-D (release
state machine) where they naturally belong, so each fix lands with the
regression tests and migration it needs rather than being rushed.
