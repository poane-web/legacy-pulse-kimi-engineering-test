# Legacy Pulse V2 — Final Summary Report

**Branch:** `security/v2-nodejs-track`
**Baseline:** the V1 Node/Express MVP (commits `b1e13bf`–`0a09dc3`)
**V2 work:** 17 commits, `41d0bb4`–`ba51b15`, across 6 checkpoints
(V2.0-A through V2.0-F)

This report is the single-document answer to the original task's closing
request: security findings, changes implemented, database changes, new
tests, remaining risks, V3 recommendations, and exact reproduction
commands. The checkpoint-specific documents in `docs/`
(`V2_SECURITY_AUDIT.md`, `V2_0_B_CHECKPOINT.md`, `V2_0_C_PLAN.md`/
`V2_0_C_CHECKPOINT.md`, `V2_0_D_PLAN.md`/`V2_0_D_CHECKPOINT.md`,
`V2_0_E_PLAN.md`/`V2_0_E_CHECKPOINT.md`,
`V2_0_F_PRODUCTION_READINESS.md`) contain the full detail this
summarizes.

---

## Security findings (from V2.0-A's audit, validated against the actual code)

| ID | Severity | Finding | Status |
|---|---|---|---|
| C1 | Critical | Dev-mode fallback secrets deterministically derivable from public source code | **Fixed** (V2.0-B) |
| C2 | Critical | Trusted-contact invite claiming had no email-ownership check | **Fixed** (V2.0-B) |
| H1 | High | Access tokens survived account-disable/password-change until natural expiry | **Fixed** (V2.0-B) |
| H2 | High | Release side-effects were not transactional | **Fixed** (V2.0-D) |
| H3 | High | Messages created after the confirmation threshold was met never auto-released | **Fixed** (V2.0-D) |
| H4 | High | File-type validation trusted the spoofable client `Content-Type` only | **Fixed** (V2.0-B) |
| M1 | Medium | AES-256-GCM ciphertexts had no AAD binding to owner/row | **Fixed** (V2.0-C) |
| M2 | Medium | No CSRF defense-in-depth on cookie-authenticated endpoints | **Fixed** (V2.0-B) |
| M3 | Medium | Seed script had no production guard | **Fixed** (V2.0-B) |
| M4 | Medium | Photo downloads weren't audit-logged | **Fixed** (V2.0-B) |
| M5 | Medium | No explicit trust-proxy policy | **Fixed** (V2.0-C) |
| M6 | Medium | Unbounded refresh-token/audit-log growth | **Partially fixed** (V2.0-C: manual cleanup script for refresh_tokens; audit_logs retention remains an undecided compliance question) |
| L1 | Low | No breached-password check | **Not fixed** — deferred, see V3 recommendations |
| L2 | Low | No per-user storage quota | **Not fixed** — deferred, see V3 recommendations |
| L3 | Low | MFA schema existed, unused | **Fixed** (V2.0-C) — full TOTP implementation |
| L4 | Low | No account lockout after repeated failed logins | **Fixed** (V2.0-C) |

Plus a new finding surfaced while working V2.0-E: **only `legacy_messages`
can ever be released to a beneficiary** — memories, photos, documents, and
the life-event timeline have no release mechanism at all. Not a numbered
audit finding (found later, during V2.0-E), explicitly not fixed, flagged
as the top V3 recommendation below.

---

## Changes implemented, by checkpoint

**V2.0-A** — Audit only. Re-validated every V1 control against the actual
implementation (not the V1 threat-model document's claims). Produced the
16 findings above.

**V2.0-B** — Fixed C1, C2, H1, H4, M2, M3, M4. New `users.token_version`
column (migration `002_add_token_version.js`). New
`utils/fileSignature.js` (magic-byte validation, zero new dependencies).
New `middleware/csrfHeader.js`.

**V2.0-C** — Fixed M1, L4, M5, M6 (partial), L3. New versioned/AAD-bound
encryption format in `utils/crypto.js` (V1 ciphertexts unaffected, zero
migration). New `utils/totp.js` (RFC 6238, zero new dependencies, verified
against official test vectors). New migration
`003_v2_0_c_auth_hardening.js` (lockout columns + `enc_format` tracking).
New `db/cleanup.js` script.

**V2.0-D** — Fixed H2, H3. New `services/legacyMessageRelease.js`: the
single, transactional, idempotent module that now owns every
`pending → released` transition in the system. No database changes.

**V2.0-E** — Hardened photo/memory/life-event attachment rules (mutual
exclusivity, scoped filtering, re-attachment endpoint). No database
changes. Identified and explicitly deferred the beneficiary-content-release
gap noted above.

**V2.0-F** — Graceful shutdown (verified live via real `SIGTERM`),
DB-aware health check, reference `Dockerfile`/`docker-compose.yml`
(explicitly flagged as unverified — no Docker available in this
environment), and this report plus the full production-readiness gap
analysis.

---

## Database changes (cumulative)

Two migrations beyond V1's baseline schema, both purely additive and
verified safe against a simulated existing V1 database (not just
asserted):

1. **`002_add_token_version.js`**: `users.token_version INTEGER NOT NULL
   DEFAULT 0`
2. **`003_v2_0_c_auth_hardening.js`**: `users.failed_login_count INTEGER
   NOT NULL DEFAULT 0`, `users.locked_until TEXT`,
   `documents.enc_format TEXT NOT NULL DEFAULT 'v1'`,
   `photos.enc_format TEXT NOT NULL DEFAULT 'v1'`

`backend/src/db/migrate.js` was rewritten from "apply `schema.sql` once"
into a real incremental-migration runner (baseline schema + numbered
migration files, each tracked individually in `schema_migrations`), which
is what made both of the above safe to add without touching existing
columns or requiring any data transformation.

No V2.0-D, V2.0-E, or V2.0-F changes required a database migration.

---

## New tests

**Total: 102 tests across 16 suites** (up from V1's 32), all passing.

| Checkpoint | New test files | New tests |
|---|---|---|
| V2.0-B | `v2b_c1_devSecrets`, `v2b_c2_and_m2_m3`, `v2b_h1_tokenVersion`, `v2b_migration`, `photos.test.js` (V1 had none) | ~25 |
| V2.0-C | `v2c_m1_aadEncryption`, `v2c_l4_m5_m6`, `v2c_l3_mfa` | 27 |
| V2.0-D | `v2d_h2_h3_release` | 6 |
| V2.0-E | `v2e_lifeEventArchitecture` | 10 |
| V2.0-F | `v2f_healthCheck` | 2 |

Every fix has at least one regression test that fails against the
pre-fix code and passes against the fix — not just a happy-path test that
would pass regardless. The highest-stakes fixes (H1 token revocation, H2
transactional rollback, H3 release-on-creation, L3's token-confusion
prevention in both directions) were additionally verified against a real,
live-running server via manual `curl`/process-signal reproduction, not
just the Jest suite.

---

## Remaining risks (honest, not hidden)

**Application-level, not yet addressed:**
- L1 (no breached-password check), L2 (no per-user storage quota)
- MFA has no recovery-code mechanism (identified in V2.0-C)
- No mechanism for beneficiaries to receive anything except text legacy
  messages (identified in V2.0-E) — the most significant remaining
  product-architecture gap
- `audit_logs` retention policy is undecided (a compliance question, not
  a technical one)
- No distributed lock for multi-process release-scheduler coordination
  (safe/idempotent per V2.0-D, but wasteful at scale)

**Infrastructure-level, cannot be fixed by more application code** — see
`docs/V2_0_F_PRODUCTION_READINESS.md` for the full categorized list:
KMS/envelope encryption/key rotation, managed secrets, external object
storage, database engine graduation (SQLite→Postgres), a shared
rate-limit store for horizontal scaling, managed MFA/identity provider
integration, structured logging/metrics/error-tracking/alerting, backups
and disaster recovery, data residency/GDPR/legal review, penetration
testing, load testing, dependency-scanning CI gates, and TLS termination
(assumed to be handled by a reverse proxy this app doesn't include).

---

## V3 recommendations, in priority order

1. **Design and build a beneficiary content-release model** for memories,
   photos, documents, and the life-event timeline — not just text legacy
   messages. This is the single highest-value remaining gap for the
   product's actual purpose, identified during V2.0-E but deliberately
   not built there since it's new feature work, not a hardening pass.
2. **MFA recovery codes.** A real gap for real users — losing a phone
   currently means no self-service account recovery once MFA is enabled.
3. **Migrate to Postgres** and address every "at scale" caveat V2.0-D and
   V2.0-F flagged (distributed lock/single-writer scheduler, connection
   pooling, replication).
4. **KMS-backed envelope encryption**, using the versioned ciphertext
   format V2.0-C already built as the migration path — a `v3:` prefix,
   new key ID, gradual re-encryption on next write rather than a risky
   flag-day migration.
5. **A real security review**: third-party penetration testing before any
   production launch with real user data. Everything in V2.0-A–E was
   self-audited; that is not a substitute for independent adversarial
   review.
6. **Observability**: structured logging + error tracking + basic metrics
   are the highest-value, lowest-effort items in the V2.0-F gap list —
   worth doing before the heavier infrastructure items (KMS, Postgres
   migration) since they'd make debugging *those* migrations much easier.

---

## Exact commands to reproduce everything in this report

```bash
git clone -b security/v2-nodejs-track \
  https://github.com/poane-web/legacy-pulse-kimi-engineering-test.git
cd legacy-pulse-kimi-engineering-test/backend
npm install
cp ../.env.example .env
# Fill in JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, DATA_ENCRYPTION_KEY:
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"   # x2, for the JWT secrets
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))" # for DATA_ENCRYPTION_KEY

npm run migrate    # applies 002_add_token_version + 003_v2_0_c_auth_hardening
npm run seed       # optional: demo data
npm test           # expect 102/102 passing across 16 suites

npm start          # serves API + frontend on http://localhost:4000
```

To re-verify specific high-stakes fixes manually, see the "Exact commands
to reproduce" section in each checkpoint's `docs/V2_0_*_CHECKPOINT.md` —
each includes the actual `curl`/process-signal commands used to validate
that checkpoint live, not just the automated test invocation.
