# Legacy Pulse V2 — Checkpoint V2.0-C: Authentication & Key Management

Scope (per `docs/V2_SECURITY_AUDIT.md`, "Areas out of scope for V2 Phase 1"
and the Medium/Low tier): **M1, M5, M6**, plus **L4** (account lockout) and
**L3** (MFA schema exists but is fully unused). These were explicitly
deferred out of V2.0-B because they involve either a data-format migration
with backward-compatibility implications (M1) or a genuinely new feature
surface (MFA), not a same-shape bug fix.

## 1. Key management: AAD-bound, versioned encryption (M1)

**Problem restated:** V1's AES-256-GCM ciphertexts authenticate only the
plaintext bytes, not which row/table/owner they belong to. A ciphertext
blob copied into a different row of the same shape would still decrypt
"successfully."

**Design:**
- Introduce a **versioned ciphertext format**. Legacy (V1) values remain
  exactly `iv:authTag:ciphertext` (no prefix) and continue to decrypt
  exactly as before — **zero migration required for existing data**, and
  no behavior change for anyone not touching this code path.
- New encryptions use format `v2:iv:authTag:ciphertext` and bind a
  caller-supplied **context string** as GCM Additional Authenticated Data
  (AAD). `decryptField`/`decryptBuffer` auto-detect the format by prefix;
  for `v2:` values, the caller must supply the *same* context string used
  at encryption time, or decryption fails closed (wrong AAD → GCM auth tag
  mismatch → throws), even though the raw key is correct.
- **Context granularity is owner-scoped, not row-scoped**, e.g.
  `"memories.content:owner:42"`. Row-level binding would require encrypting
  *after* the row's ID is known (a two-phase insert-then-update, adding
  real complexity for every write path) for a marginal additional gain
  over owner-scoped binding, which already defeats the attack class the
  audit finding describes: a ciphertext blob copied into a different
  **owner's** row (the actual confidentiality boundary this app cares
  about) will fail to decrypt, because the AAD embeds the original
  owner's ID. This is a deliberate, documented proportionality decision,
  not an oversight.
- This also **lays the groundwork for key rotation** (not implemented in
  V2.0-C — see "Remaining" below): because the format is now versioned, a
  future `v3` prefix could select a different key ID (envelope encryption)
  without breaking `v1`/`v2` data still on disk, mid-rotation.

**What is NOT done here (explicitly deferred to V2.0-F):** a KMS, multiple
live key IDs, or automatic re-encryption/rotation of existing data. This
checkpoint makes rotation *possible in the future*; it does not implement
rotation itself, since that requires real infrastructure (a KMS or
equivalent) this MVP doesn't have.

## 2. Account lockout after repeated failed logins (L4)

V1 only had IP-based rate limiting; a distributed low-and-slow attacker
(many IPs, few attempts each) wasn't slowed at the account level. Adds
`users.failed_login_count` and `users.locked_until`: 5 consecutive failed
attempts locks the account for 15 minutes (both configurable), reset to 0
on any successful login. This is layered on top of, not instead of, the
existing IP rate limiter.

## 3. TOTP-based multi-factor authentication (L3)

The schema (`users.mfa_enabled`, `mfa_secret_encrypted`) existed but no
code path used it. Implements standard TOTP (RFC 6238, HMAC-SHA1, 30s
step, 6 digits) with **zero new npm dependencies** — built on Node's
built-in `crypto` module (`utils/totp.js`).

Flow:
- `POST /api/security/mfa/setup` — generates a new secret (not yet
  active), returns a `otpauth://` provisioning URI for an authenticator
  app.
- `POST /api/security/mfa/verify-setup` — the user proves they configured
  it correctly by submitting a current code; only then is `mfa_enabled`
  flipped to `1`.
- `POST /api/security/mfa/disable` — requires the current password.
- **Login flow change:** if `mfa_enabled`, `POST /auth/login` no longer
  returns real tokens after a correct password. It returns a short-lived
  (5 min) `mfaChallengeToken` instead. `POST /api/auth/mfa/verify` accepts
  that token plus a TOTP code and, only then, issues real access/refresh
  tokens exactly as a normal login would.
- **Token-confusion prevention:** access tokens now carry an explicit
  `typ: 'access'` claim; `requireAuth` rejects anything without it. The
  MFA challenge token carries `typ: 'mfa_challenge'` and is signed with
  the same secret but is structurally rejected by `requireAuth` even
  though it shares a signing key — it simply isn't shaped like an access
  token and can't be used to reach any protected route. (A pre-V2.0-C
  token with no `typ` claim at all is treated as `access` for backward
  compatibility, mirroring the `tokenVersion` default-to-0 approach from
  V2.0-B.)

**Explicitly out of scope, documented not hidden:** this is *application-
managed* TOTP, not integration with a managed MFA/identity provider
(Okta, Duo, etc.) — that remains a V2.0-F production-readiness item, as
already flagged in the original V1 threat model. There's also no backup/
recovery-code mechanism yet (a user who loses their authenticator app and
device has no self-service recovery path) — flagged as a known gap below.

## 4. Explicit trust-proxy policy (M5)

`app.js` now explicitly sets Express's `trust proxy` based on a new
`TRUST_PROXY` env var (default: `false`, i.e. explicitly *not* trusting
any forwarded-for header — the safe default for this MVP's
direct-to-internet single-process deployment). Documented in
`.env.example` with the exact guidance for what to set it to if/when this
is ever deployed behind a real reverse proxy/load balancer.

## 5. Retention cleanup for refresh tokens (M6, partial)

Adds `npm run cleanup` — a script that deletes `refresh_tokens` rows that
are both revoked/expired **and** older than a retention window (default 30
days). Deliberately conservative (only touches rows that are already
dead weight, never a currently-valid session). This is a manually-invoked
script in V2.0-C, not an automated cron job — wiring it into a scheduled
job (and deciding a retention policy for `audit_logs`, which has different,
likely longer, compliance-driven retention needs) is a deployment/ops
decision appropriately deferred to V2.0-F.

## Database changes

New migration `003_v2_0_c_auth_hardening.js`:
- `users.failed_login_count INTEGER NOT NULL DEFAULT 0`
- `users.locked_until TEXT NULL`

Both additive, defaulted, safe for existing databases — same pattern as
`002_add_token_version.js`. No changes to existing columns; `mfa_enabled`/
`mfa_secret_encrypted` already existed in the V1 schema and are now
actually used.
