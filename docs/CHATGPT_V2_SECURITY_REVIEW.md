# Legacy Pulse — ChatGPT V2 Security Engineering Review

## Scope

This review was performed against the actual source tree on `main`, independently of the other model reports. The repository contains a Node/Express API, SQLite persistence, JWT access tokens with refresh cookies, AES-256-GCM field/file encryption, owner-based authorization, trusted contacts, beneficiaries, legacy-message release logic, and a vanilla JS frontend.

## Independent findings

### Critical

**C1 — Source-derived development secrets.** The original configuration derived fallback JWT and data-encryption secrets from constant source strings whenever `NODE_ENV` was anything other than exactly `production`. In a public repository, that makes the fallback values predictable and could enable token forgery or decryption if a non-production deployment is exposed. V2 replaces this with process-random ephemeral development secrets and retains hard failure for missing production secrets.

**C2 — Trusted-contact invitation was not identity-bound.** The original trusted-contact claim endpoint validated possession of the invitation token but did not require the authenticated account email to match the invitation's intended email. V2 adds that binding.

### High

**H1 — Access-token revocation gap.** The original middleware trusted JWT claims without consulting current account state. Disabling an account therefore revoked refresh tokens but did not immediately invalidate a previously issued access token. V2 re-checks account status and authorization fields against the database and records `password_changed_at`; tokens issued before a password change are rejected.

**H2 — Release side effects lacked a transaction.** Trusted-contact confirmation and scheduled release paths could partially apply state changes if the process failed between statements. V2 makes the confirmation/release state transition transactional and uses conditional status updates. Notification delivery remains outside the transaction; this is intentionally a future durable-outbox concern.

**H3 — Trusted-contact release was event-poor.** The original implementation stored confirmations globally per owner and used the current confirmation count to release all pending messages. This is not yet a complete estate-grade release model. V2 treats this as a next architectural checkpoint: confirmations should belong to a versioned release case/event, not permanently to the owner. The current branch hardens the existing transition but does not claim this redesign is complete.

**H4 — File type checks trusted multipart MIME.** V2 adds server-side magic-byte/signature validation for PDF, JPEG, PNG, GIF, WebP, legacy Office documents, OOXML documents and text files. Client MIME remains an input, not the security boundary.

### Medium / architectural

- AES-GCM currently lacks AAD binding between ciphertext and logical record identity.
- Encryption still uses one application key; envelope encryption/KMS is a later checkpoint.
- Audit logs are append-by-convention rather than cryptographically tamper-evident.
- Photo downloads were not previously audited; V2 adds the missing audit event.
- Cookie-only refresh/logout endpoints now require a non-simple request header as CSRF defense-in-depth, in addition to SameSite=Strict and CORS.
- Demo seed is now explicitly forbidden in production.
- SQLite migration handling now supports numbered forward migrations.

## V2 implementation in this branch

- `chatgpt-v2` branch created from the repository's `main` branch.
- Removed source-derived secret fallbacks.
- Bound trusted-contact claims to intended email identity.
- Added current-account checks to authentication middleware.
- Added password-change timestamp based access-token invalidation.
- Added transactional refresh-token rotation.
- Added request-integrity header to cookie-authenticated endpoints and frontend client.
- Added server-side file signature validation.
- Added photo download audit logging.
- Added production guard to demo seed.
- Added password timestamp schema + migration support.
- Added GitHub Actions security test workflow.

## Not claimed as complete

This branch is **not production-ready** merely because automated tests pass. Remaining work includes:

1. Release-case/state-machine redesign with per-event confirmations.
2. Durable notification/outbox processing.
3. Envelope encryption and KMS/HSM integration.
4. AAD-bound encryption with versioned ciphertext formats.
5. MFA implementation and recovery controls.
6. Tamper-evident/externally retained audit logs.
7. Storage quotas and retention/archival policy.
8. Production object storage and malware/file scanning strategy.
9. Monitoring, alerting, backups, disaster recovery and key recovery.
10. Independent penetration testing and deployment review.

## Verification status

The GitHub connector was used to inspect and modify the repository, but this execution environment does not provide a direct local clone/runtime capable of installing the native `better-sqlite3` dependency. A GitHub Actions workflow was therefore added to execute `npm ci` and the Jest suite on the branch. The branch must not be described as test-passing until that workflow reports success.
