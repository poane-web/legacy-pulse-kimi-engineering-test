# Legacy Pulse V3 — Production Readiness

This document extends `docs/V2_0_F_PRODUCTION_READINESS.md` (which
remains accurate and is not duplicated here) with what V3's adversarial
pass specifically surfaced under category K, plus the concrete deferred
items named in `docs/security/V3-THREAT-MODEL.md`. Read both documents
together; this one does not repeat V2.0-F's KMS/object-storage/database-
engine/observability/backup/compliance/testing/TLS sections, which are
still the primary reference for those topics.

## What changed in this pass (application-layer, verified)

- V3-H1 (invite-claim atomicity), V3-H2 (beneficiary-deletion data-loss
  guard), V3-M1 (duplicate-confirmation error handling), V3-M2 (orphaned
  file cleanup on account deletion), V3-M3 (confirmation-status
  visibility), V3-L1 (filename header sanitization) — see
  `V3-THREAT-MODEL.md` for full detail on each. All six fixed, tested,
  and verified against the actual running application.

## Deferred, prioritized (next checkpoint)

1. **Step-up authentication for release-authority-affecting actions.**
   `DELETE /trusted-contacts/:id` and `DELETE /beneficiaries/:id` should
   require password re-confirmation, matching the existing pattern
   already used correctly for `PUT /users/password`,
   `POST /security/mfa/disable`, and `DELETE /users/me`. Deferred this
   pass specifically to keep the fix set bounded and independently
   reviewable rather than changing every mutation endpoint's auth
   requirements in one sweep — this is the single highest-priority
   deferred item.
2. **Confirmation expiry.** `release_confirmations` never expire
   (V3-D2). A time-based expiry window (e.g. confirmations older than N
   days no longer count toward the release threshold) would close the
   "mistaken confirmation stays primed forever" gap that V3-M3's
   visibility endpoint only partially mitigates (visibility, not
   automatic remediation).
3. **Password-reset flow.** Does not exist at all (see
   `V3-THREAT-MODEL.md` §A). Needs to be built carefully — it is exactly
   the kind of feature where the invite-claim TOCTOU class of bug
   (V3-H1) is likely to recur if not designed with the same atomic-
   conditional-update discipline from the start.
4. **MFA recovery codes** — already named in V2.0-C/F, restated here as
   still outstanding and now cross-referenced against the "no admin
   impersonation feature" finding (J): today, a user locked out of both
   their password and their MFA device has **no recovery path of any
   kind**, self-service or admin-assisted. This is a compounding gap
   across two checkpoints' worth of findings, not just one.

## Category K: production infrastructure, organized against V3's explicit list

This restates V2.0-F's content in the structure V3's prompt specifically
requested, with V3's new findings folded in where they sharpen a
requirement:

| Requirement | Status | Notes |
|---|---|---|
| PostgreSQL | Not present (SQLite only) | See `V3-THREAT-MODEL.md` §H — the migration must preserve the atomic-conditional-UPDATE pattern everywhere it's now used (`legacyMessageRelease.js`, the V3-H1 invite-claim fix); a naive port that reintroduces check-then-act patterns would reintroduce V3-H1-class bugs |
| KMS/HSM | Not present | Single symmetric key from an env var; V2.0-C's versioned ciphertext format is the intended migration path, not yet executed |
| Secrets management | Not present | `.env` files only; needs Vault/Secrets Manager/equivalent with runtime injection |
| Object storage | Not present (local disk) | V3-M2's cleanup fix must be replicated in whatever `storage.remove()` becomes for S3/GCS |
| TLS | Not present in-app | Assumed handled by a reverse proxy/platform in front of this app (correct architecture, but must actually be configured) |
| Backups | Not present | No RPO/RTO defined yet |
| Disaster recovery | Not present | Depends on backups existing first |
| Monitoring | Not present | No metrics/dashboards |
| Alerting | Not present | Nobody is paged for anything, including the health check going `503` |
| SIEM | Not present | `audit_logs` is DB-only, not shipped anywhere external; V3's finding (I) that it is *not* cryptographically tamper-evident (only application-level-immutable) makes this more urgent, not less |
| Rate limiting | In-process only | `express-rate-limit`'s default in-memory store; V2.0-F already flagged this doesn't mean anything once horizontally scaled — needs Redis |
| WAF | Not present | No web application firewall in front of this app; not evaluated as part of this application-security pass, since a WAF is an infrastructure control layered in front of, not inside, the application |
| Worker isolation | Not applicable yet | Single process; becomes relevant once horizontally scaled — see V3-C2's note that the scheduler currently runs in every process, which is safe but wasteful, not isolated |
| Deployment security | Not evaluated | No CI/CD pipeline exists to secure (V2.0-F) |
| Key rotation | Not present | Architecturally enabled (versioned ciphertext) but not implemented |
| Database migrations | Present, and reviewed here | The incremental migration runner (`migrate.js`, built in V2.0-C) was specifically reviewed against V3's adversarial lens: each migration file's `up()` function uses `PRAGMA table_info` guards for idempotency and runs inside its own `db.transaction()` (added when the runner was built) — this pattern was re-verified, not just assumed, and holds up |
| Incident response | Not present | No runbook, no defined process for responding to a suspected breach, no pre-drafted user-notification plan |

## Explicit statement, per the prompt's requirement not to declare readiness

**Passing 117/117 tests, and every fix in this document being real,
implemented, and verified — does not mean this system is production-ready.**
The application-security work across V2 and V3 addresses what code
running on this application server can control. It does not, and
structurally cannot, address anything in the table above. A system
handling "highly sensitive legacy messages, documents, memories, trusted
contacts, beneficiaries, milestone releases, and eventually financial
milestone instructions" — the exact scope named in this task — needs
every row of that table addressed, plus the deferred application-layer
items listed above, plus genuine third-party penetration testing and
load testing against real production infrastructure (not this SQLite/
single-process evaluation environment), before it should hold one real
person's real data.
