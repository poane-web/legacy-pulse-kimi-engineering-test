# Legacy Pulse V2 — Checkpoint V2.0-C: Authentication & Key Management

Scope, per `docs/V2_0_C_PLAN.md`: **M1, L4, M5, M6, L3** — the findings
deferred out of V2.0-B because they involve either a data-format
migration with backward-compatibility implications (M1) or a genuinely new
feature surface (MFA), not a same-shape bug fix.

## Changes implemented

### M1 (Medium) — AAD-bound, versioned field/file encryption
**Files:** `backend/src/utils/crypto.js`, `backend/src/utils/encryptionContext.js`
(new), `backend/src/services/storage.js`, every route touching encrypted
content (`memories`, `timeline`, `legacyMessages`, `documents`, `photos`,
`search`)

Ciphertexts are now versioned: legacy `iv:authTag:ciphertext` (V1, no AAD)
continues to decrypt exactly as before — **zero migration of existing
data**. New encryptions use `v2:iv:authTag:ciphertext` and bind an
owner-scoped context string (e.g. `memories.content_encrypted:owner:42`)
as GCM Additional Authenticated Data. Decrypting a v2 value with the wrong
(or missing) context fails closed. This defeats the specific attack the
audit finding described: a ciphertext blob copied into a different
owner's row no longer decrypts "successfully." Context is owner-scoped,
not row-scoped — a deliberate proportionality decision documented in
`docs/V2_0_C_PLAN.md` §1, since row-level binding would require a
two-phase insert-then-encrypt rewrite of every write path for marginal
extra protection over what owner-scoping already achieves.

`documents`/`photos` gained an `enc_format` column (migration
`003_v2_0_c_auth_hardening.js`) so `storage.read()` knows whether to
supply AAD when decrypting a given file.

### L4 (Low) — Account lockout after repeated failed logins
**File:** `backend/src/routes/auth.routes.js`

5 consecutive failed logins (configurable via `ACCOUNT_LOCKOUT_THRESHOLD`)
locks the account for 15 minutes (`ACCOUNT_LOCKOUT_MINUTES`), layered on
top of — not instead of — the existing IP-based rate limiter. A locked
account rejects even the correct password until the lock expires. Resets
to 0 on any successful login.

### M5 (Medium) — Explicit trust-proxy policy
**File:** `backend/src/app.js`

`app.set('trust proxy', ...)` is now explicit and driven by
`TRUST_PROXY` (default `false`), replacing reliance on Express's implicit
default. Verified with a test that a spoofed `X-Forwarded-For` header is
correctly ignored and never recorded in the audit log.

### M6 (Medium, partial) — Refresh-token retention cleanup
**File:** `backend/src/db/cleanup.js` (new), `npm run cleanup`

Deletes `refresh_tokens` rows that are both revoked/expired **and** older
than a retention window (default 30 days) — deliberately conservative,
never touches a currently-valid session. Manually invoked in this
checkpoint; scheduling it as a cron job, and deciding `audit_logs`
retention (a compliance decision, not a mechanical one), are deferred to
V2.0-F.

### L3 (Low) — TOTP-based multi-factor authentication
**Files:** `backend/src/utils/totp.js` (new), `backend/src/utils/jwt.js`,
`backend/src/middleware/auth.js`, `backend/src/routes/{auth,security}.routes.js`

The `users.mfa_enabled`/`mfa_secret_encrypted` columns existed since V1
with no code path using them. Implements RFC 6238 TOTP (HMAC-SHA1, 30s
step, 6 digits) with **zero new npm dependencies**, verified against all 3
official RFC 6238 Appendix B test vectors.

- `POST /security/mfa/setup` → generates a secret + `otpauth://`
  provisioning URI (not yet active)
- `POST /security/mfa/verify-setup` → activates MFA only once the user
  proves they configured it correctly
- `POST /security/mfa/disable` → requires current password
- `GET /security/mfa/status`
- **Login flow:** if MFA is enabled, `POST /auth/login` returns a
  short-lived (5 min) `challengeToken` instead of real tokens after a
  correct password; `POST /auth/mfa/verify` consumes it + a TOTP code to
  issue the real session.

**Token-confusion prevention:** access tokens now carry `typ: 'access'`;
`requireAuth` rejects anything without it. The MFA challenge token carries
`typ: 'mfa_challenge'`, signed with the same secret but structurally
rejected by `requireAuth`. Verified with tests in **both directions** — a
challenge token can't reach a protected route, and a real access token
can't be used to complete MFA verification. A token with no `typ` claim at
all (issued before this checkpoint) defaults to `access`, mirroring the
`tokenVersion` backward-compatibility approach from V2.0-B.

**Explicitly out of scope, documented not hidden:** this is
application-managed TOTP, not integration with a managed MFA/identity
provider — that remains a V2.0-F item. There is no backup/recovery-code
mechanism for a user who loses their authenticator device — a real gap,
flagged here rather than silently left for someone to discover.

## Database changes

Migration `003_v2_0_c_auth_hardening.js` — additive only, safe for
existing databases, same pattern as `002_add_token_version.js`:
- `users.failed_login_count INTEGER NOT NULL DEFAULT 0`
- `users.locked_until TEXT NULL`
- `documents.enc_format TEXT NOT NULL DEFAULT 'v1'`
- `photos.enc_format TEXT NOT NULL DEFAULT 'v1'`

`users.mfa_enabled`/`mfa_secret_encrypted` required no migration — they
already existed in the V1 schema.

## New tests

27 new tests across 3 files, all passing alongside the full suite:

| File | Covers |
|---|---|
| `v2c_m1_aadEncryption.test.js` | AAD round-trip, wrong-context rejection (the actual attack the finding describes), missing-context rejection, legacy v1 values unaffected, tamper detection preserved — for both field and buffer encryption |
| `v2c_l4_m5_m6.test.js` | Lockout after threshold, correct-password-still-rejected-while-locked, counter reset on success, lock expiry, spoofed X-Forwarded-For ignored, cleanup script only removes dead rows |
| `v2c_l3_mfa.test.js` | Full setup→verify→login-challenge→verify flow, wrong code rejected, disable requires password, **both directions** of the token-confusion attack, garbage/expired challenge tokens rejected, double-setup rejected, RFC 6238 vector verification, malformed-code rejection |

**Full suite: 95/95 passing.** Also manually smoke-tested end-to-end
against a live server (not just the test DB): migrations apply cleanly,
registered a real user, completed MFA setup with a hand-computed TOTP
code, confirmed login correctly returns `mfaRequired: true` with no
access token once MFA is active.

## Remaining from the V2.0-A audit

- **H2, H3** (non-transactional release side-effects; messages created
  after the confirmation threshold is met never auto-release) →
  **V2.0-D — Legacy release state machine**, next.
- **L1, L2** (breached-password check, per-user storage quota),
  **MFA recovery codes** (new gap identified in this checkpoint) →
  candidates for **V2.0-F**.
- KMS/envelope encryption, live key rotation, managed MFA provider
  integration remain explicitly out of scope for any V2 checkpoint — see
  `docs/V2_0_C_PLAN.md` for why these need real infrastructure this MVP
  doesn't have.

## Exact commands to reproduce

```bash
cd backend
npm install
cp ../.env.example .env
# fill in JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, DATA_ENCRYPTION_KEY
npm run migrate   # applies 002_add_token_version and 003_v2_0_c_auth_hardening
npm run seed
npm test          # expect 95/95 passing
```

To manually verify the MFA flow against a live server:

```bash
npm start &
curl -s -H "X-Legacy-Pulse-Client: 1" -H "Content-Type: application/json" \
  -X POST http://localhost:4000/api/auth/register \
  -d '{"email":"test@example.com","password":"SuperSecret99","fullName":"Test User"}'
# copy accessToken from the response, then:
curl -s -X POST http://localhost:4000/api/security/mfa/setup \
  -H "Authorization: Bearer <accessToken>"
# scan the provisioningUri with an authenticator app (or compute a code
# from the returned secret), then:
curl -s -X POST http://localhost:4000/api/security/mfa/verify-setup \
  -H "Authorization: Bearer <accessToken>" -H "Content-Type: application/json" \
  -d '{"code":"<6-digit code>"}'
# now log in again — expect {"mfaRequired":true,"challengeToken":"..."}
# instead of an accessToken
curl -s -H "X-Legacy-Pulse-Client: 1" -H "Content-Type: application/json" \
  -X POST http://localhost:4000/api/auth/login \
  -d '{"email":"test@example.com","password":"SuperSecret99"}'
```
