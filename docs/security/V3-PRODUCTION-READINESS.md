# Legacy Pulse V3 — Production Readiness

## Verdict

**PRE-PRODUCTION**

This branch is not a production deployment candidate yet. The temporal release core has materially stronger invariants, but several production controls require infrastructure and integration work that cannot be established by unit tests alone.

## What V3 establishes

### Release integrity

- Scheduled releases use an atomic claim guarded by state, release type, release time, and configuration version.
- A stale owner edit cannot overwrite a release that has already been claimed.
- Duplicate scheduler execution produces one durable state transition.
- Trusted-contact confirmation is scoped to one message and one contact.
- The release recipient is snapshotted at the first trusted-contact authorization step.
- A later recipient identity mutation fails closed rather than redirecting the release.
- The final trusted-contact release copies the snapshot into `released_recipient_user_id`.
- Local release notification and release audit are committed in the same transaction as the release.
- Notification failure therefore rolls the release back and permits a safe retry.

### Authentication

- Disabled accounts are checked on every authenticated request.
- Password-change timestamps invalidate older access JWTs.
- Refresh tokens are stored hashed and rotated.
- Refresh-token reuse is rejected by transactional rotation.

## Remaining blockers

| Area | Status | Blocking reason |
|---|---|---|
| PostgreSQL | BLOCKED | SQLite is not sufficient evidence for production concurrency/load behaviour |
| External notifications | BLOCKED | Need transactional outbox, relay, provider delivery tracking, and idempotent consumers |
| MFA | BLOCKED | Production login/step-up MFA must be fully enforced and recovery paths audited |
| Encryption | BLOCKED | KMS/HSM-backed envelope encryption and rotation are required |
| Object storage | BLOCKED | Encrypted private storage, lifecycle policy, malware scanning and signed/authorized access required |
| Secrets | BLOCKED | Managed secret store and rotation required |
| Audit | BLOCKED | External immutable/WORM retention and SIEM integration required |
| Backups/DR | BLOCKED | Restore drills and defined RPO/RTO required |
| Independent security test | BLOCKED | Application adversarial tests are not a substitute for independent penetration testing |
| Financial milestones | BLOCKED | Bank/regulated-partner integration, legal review, reconciliation and callback authentication required |

## Exactly-once statement

Legacy Pulse can make the **database state transition exactly once** by using an atomic claim and a unique release/event identifier.

It cannot honestly promise exactly-once delivery to email, SMS, push providers, banks, or other external systems. Those integrations should use a transactional outbox and idempotency keys. The outbox guarantees that a committed release produces a durable event; the external consumer must tolerate duplicate delivery. citeturn1search0turn1search4

## PostgreSQL migration requirements

Before production:

1. Port all migrations to PostgreSQL/Alembic or an equivalent migration system.
2. Add unique constraints for release claims, event IDs, confirmation tuples, and milestone payout instructions.
3. Replace SQLite-specific date functions and transaction assumptions.
4. Use row locking or atomic conditional writes for every multi-step release transition. PostgreSQL's default Read Committed isolation gives each statement a current committed snapshot, so multi-statement read/validate/write logic must be explicitly protected. citeturn0search1turn0search6
5. Load-test two, ten, and many concurrent workers against the real PostgreSQL deployment.
6. Test deadlock and serialization-failure retry paths.

## Life Vault milestone readiness

The milestone product is architecturally feasible but should be a separate V3/V4 bounded context. The financial leg should use a regulated institution as custodian.

Example milestone:

`child DOB + 18 years -> eligibility -> release claim -> bank instruction -> bank acknowledgement -> message/video release -> notification`

The milestone record should contain:

- immutable milestone ID
- subject identity reference
- authoritative DOB source/reference
- timezone policy
- eligibility version
- financial instruction ID (not money held by Legacy Pulse)
- release state/version
- idempotency key
- outbox event ID
- provider correlation ID
- callback status
- immutable audit events

Leap-day birthdays, timezone boundaries, DOB corrections, account closure, beneficiary replacement and duplicate callbacks must be explicit policy cases, not accidental date arithmetic.

## Final counts for this checkpoint

The exact vulnerability/test counts must be generated from the final CI run after all V3 adversarial suites are green. Do not hand-edit a count merely to declare readiness.

The final report must contain:

- total vulnerabilities discovered
- critical/high/medium/low counts
- fixed/deferred/unresolved counts
- total tests
- adversarial tests
- concurrency tests
- process/restart tests
- database tests
- PostgreSQL integration results
- production infrastructure controls

Until those gates are complete, the correct verdict remains **PRE-PRODUCTION**.
