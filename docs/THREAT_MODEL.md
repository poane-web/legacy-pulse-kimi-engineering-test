# Legacy Pulse — Threat Model (MVP)

Scope: the application as implemented in this repository. This is a
lightweight STRIDE-style pass focused on the highest-value risks for a
"secure legacy data" product, not an exhaustive audit.

## Assets

1. Owner-authored content (memories, stories, instructions, legacy messages) — confidentiality-critical.
2. Uploaded documents/photos — confidentiality-critical, may include IDs, wills, financial info.
3. Beneficiary/trusted-contact PII (names, emails, relationships).
4. Credentials (password hashes, refresh tokens, JWT signing secret, encryption key).
5. Release-condition integrity (a message must not release early, or to the wrong beneficiary).
6. Audit trail integrity.

## Actors

- **Owner** — legitimate account holder preserving their legacy.
- **Beneficiary** — should only ever see content addressed to them, only after release conditions are met.
- **Trusted contact** — can confirm a release-trigger event; should not be able to single-handedly release content, and should not be able to read content.
- **Admin** — platform operator; should see operational metadata, never decrypted user content.
- **External attacker** — no account, or a compromised/malicious account.

## Key threats & mitigations

| # | Threat | Mitigation implemented |
|---|---|---|
| T1 | Credential stuffing / brute force login | bcrypt (cost 12) + rate limiting on `/api/auth/*` (10 req/15min/IP) + audit log of failed attempts |
| T2 | Stolen/leaked JWT used indefinitely | Access tokens expire in 15 min; refresh tokens are revocable, hashed at rest, rotated on use |
| T3 | Refresh token theft via XSS | Refresh token is `httpOnly`, `SameSite=Strict` cookie — inaccessible to JS. Access token is short-lived and held in memory only, not localStorage, to limit XSS blast radius |
| T4 | Beneficiary reads a legacy message before release conditions are met | Server-side check of `status === 'released'` on every read, independent of what the client displays; unauthorized attempts are 403'd and audit-logged (`legacy_message.unauthorized_access_attempt`) |
| T5 | A single malicious/compromised trusted contact prematurely triggers release | Two-person rule: `required_confirmations` (default 2) independent trusted contacts must each confirm before trigger-based messages release |
| T6 | Beneficiary A reads content addressed to Beneficiary B | Ownership/target check compares `legacy_messages.beneficiary_id` to the requester's own linked beneficiary record, not just "any beneficiary of this owner" |
| T7 | IDOR — Owner A reads Owner B's memories/documents by guessing IDs | `requireOwnership` middleware loads the row and checks `owner_id === req.user.id` on every resource route before returning data |
| T8 | Privilege escalation — Owner sets their own role to admin | `role` is never accepted from client input on any update route; only settable via the seed script / future admin-only endpoint (not exposed in MVP) |
| T9 | Admin snoops on Owner's private content | Admin routes query only metadata tables/columns; no admin route calls `decryptField`; enforced by code review / tests asserting admin responses never include `*_encrypted` fields decrypted |
| T10 | File upload used to plant malware / path traversal | Filenames randomized (UUID) server-side, never derived from user input; MIME allow-list; size limits (`MAX_UPLOAD_MB`); files stored outside the web root and never served statically — only via an authenticated, decrypting download route |
| T11 | Sensitive data exposed via server logs or error messages | Central error handler returns generic messages in production, logs stack traces server-side only; request logger configured to never log request bodies (which could contain content or passwords) |
| T12 | Secrets committed to source control | All secrets sourced from `process.env` via `config/env.js`, which throws at startup if required secrets are missing; `.env` is git-ignored; `.env.example` ships with placeholder values only |
| T13 | SQL injection | All queries use parameterized statements via `better-sqlite3` prepared statements; no string concatenation into SQL anywhere in the codebase |
| T14 | XSS via stored content (memory text, names) rendered in frontend | Frontend renders all user content via `textContent`/explicit escaping helper, never `innerHTML` with raw user data |
| T15 | CSRF against cookie-authenticated refresh endpoint | `SameSite=Strict` on the refresh cookie mitigates cross-site submission; the refresh endpoint only rotates a token and cannot itself mutate content |
| T16 | Audit log tampering to hide unauthorized access | No update/delete endpoint exists for `audit_logs`; writes are append-only from server-side code paths only |
| T17 | Encryption key compromise decrypts all data | Out of scope to fully solve in an MVP without a KMS. Documented residual risk (see below) |

## Explicitly accepted residual risks (MVP-level, documented not hidden)

- **Single symmetric encryption key** for all field/file encryption, sourced
  from an environment variable. In production this should be a
  KMS-managed/envelope-encrypted key with per-tenant data keys and
  rotation. This MVP does not implement key rotation or envelope
  encryption.
- **No account lockout after N failed logins** (only rate limiting) — a
  determined low-and-slow distributed attacker isn't fully stopped. Rate
  limiting + audit logging is the MVP mitigation; lockout is deferred.
- **No email delivery integration** — invite tokens and notifications are
  generated and stored/logged, not actually emailed (see README "Deferred
  Features"). In production, invite tokens must never appear in
  client-visible responses; the current implementation returns the raw
  invite link in the API response *for the Owner who created it* (not to
  anyone else) as a stand-in for "email was sent", clearly marked in code
  and README.
- **No MFA enforcement in MVP UI** (schema and hashed-secret storage exist,
  but the login flow does not yet challenge for a TOTP code) — documented
  under deferred features.
- **Single-server, single-process deployment assumption** (SQLite, in-memory
  rate limiter). A multi-instance production deployment would need a
  shared store (Redis) for rate limiting and a networked database.
