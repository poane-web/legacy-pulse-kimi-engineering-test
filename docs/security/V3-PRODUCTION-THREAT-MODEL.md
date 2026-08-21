# Legacy Pulse V3 — Production Threat Model

## Scope

This document covers the FastAPI/Node temporal-hardening line represented by the `chatgpt-v3-production-candidate` branch. Previous security claims are treated as hypotheses and are re-tested against the implementation.

The central asset is **release-condition integrity**: a credential must never be released to the wrong person, at the wrong time, or without the required authority. Confidentiality of the encrypted legacy content is a separate asset.

## Security invariant

For every release:

`identity -> authority -> configuration -> eligibility -> confirmation -> authorization -> release -> recipient -> notification`

must remain internally consistent despite retries, concurrent sessions, scheduler restarts, credential changes, relationship changes, and process failure.

## State machine

The production design should use explicit states:

- `DRAFT` — mutable, not eligible for release.
- `SCHEDULED` — waiting for a time condition.
- `PENDING_CONFIRMATION` — quorum/authority is being collected.
- `AUTHORIZED` — all release predicates are satisfied and configuration is frozen.
- `RELEASE_CLAIMED` — one worker has atomically claimed the release.
- `RELEASED` — durable release and recipient snapshot committed.
- `CANCELLED` — explicitly stopped by an authorized actor.
- `EXPIRED` — eligibility window ended without release.
- `FAILED` — operational failure requiring retry or intervention; must not masquerade as `RELEASED`.

No API should be able to jump directly from a mutable state to `RELEASED` without the state-machine guard.

## Threat classes

| ID | Threat | Severity | Current position |
|---|---|---:|---|
| V3-01 | Trusted-contact final confirmation did not originally persist the release recipient | HIGH | Fixed on V3 branch with recipient snapshot + final recipient binding |
| V3-02 | Beneficiary identity mutation between confirmations could redirect a release | HIGH | Fixed on V3 branch by snapshotting identity at first confirmation and failing closed on mismatch |
| V3-03 | Trusted-contact release notification was originally outside the release transaction | HIGH | Fixed on V3 branch; local notification and release audit are transactional |
| V3-04 | External email/SMS/push delivery cannot be exactly-once with a database commit | HIGH | Deferred to transactional outbox + idempotent consumer infrastructure |
| V3-05 | SQLite transaction semantics are not evidence for production PostgreSQL concurrency | HIGH | Deferred; requires PostgreSQL integration/load testing |
| V3-06 | MFA enforcement is not present in the current login path | HIGH | Deferred until the authentication subsystem is completed and tested end-to-end |
| V3-07 | Single application encryption key remains a blast-radius risk | HIGH | Deferred to KMS/HSM-backed envelope encryption |
| V3-08 | JWTs issued before logout remain usable until expiry unless an authority timestamp changes | MEDIUM | Password-change/status checks exist; explicit access-token denylist is deferred |
| V3-09 | Audit storage is append-only by application convention, not immutable/WORM | MEDIUM | Infrastructure control required |
| V3-10 | Immediate release is intentionally owner-authorized | MEDIUM | Product decision; must require step-up authentication in production |
| V3-11 | Invite links are returned to the creating owner in the MVP | MEDIUM | Must be replaced by controlled email/SMS delivery before production |
| V3-12 | Per-user storage quotas are not enforced | LOW | Deferred |

## Adversarial guarantees verified

- Disabled owner accounts cannot use already-issued access JWTs for API mutations.
- Password-change timestamps invalidate older access JWTs.
- Scheduled releases use an atomic state/configuration claim.
- Duplicate scheduler sweeps do not create duplicate local notifications.
- Revoked trusted contacts cannot contribute a new confirmation; their dependent confirmation rows are removed by the relationship deletion.
- Owner-as-trusted-contact is rejected.
- Beneficiary deletion is blocked while messages reference the beneficiary.
- Recipient identity is frozen when trusted-contact authorization begins.
- Trusted-contact release and local notification now share one database transaction.

## Production concurrency requirements

The PostgreSQL implementation must use:

1. Atomic conditional state transitions (`UPDATE ... WHERE state = expected_state AND version = expected_version`).
2. Unique idempotency constraints for release claims and external event IDs.
3. `SELECT ... FOR UPDATE` or an equivalent row-lock strategy around release aggregates where a read/validate/write sequence cannot be represented by one conditional write. PostgreSQL documents that `FOR UPDATE` blocks conflicting writers until the transaction ends. citeturn0search2turn0search6
4. Retry handling for serialization/deadlock failures.
5. A transactional outbox for external notifications and partner integrations. The outbox makes the database commit and event creation atomic, while consumers remain idempotent because the relay may deliver an event more than once. citeturn1search0turn1search4

## Life Vault milestone threats

A future milestone engine must treat the milestone as a durable state machine, not a cron job:

`milestone_due -> eligibility_verified -> release_claimed -> financial_instruction_created -> bank_acknowledged -> message_released -> notification_sent`

The bank or other regulated financial institution remains custodian of money. Legacy Pulse should store an immutable milestone instruction/reference and coordinate the workflow, not hold regulated assets unless separately licensed and designed for that purpose.

Attacks to test include birthday/timezone boundaries, leap-day rules, DOB correction, duplicate scheduler execution, parent/child account closure, beneficiary replacement, callback replay, forged bank callbacks, payout success with notification failure, notification success with payout failure, and bank timeout/retry.

## Residual infrastructure threats

Application code alone cannot close these risks:

- KMS/HSM and key custody
- PostgreSQL high availability and backup/restore testing
- managed secrets and secret rotation
- private encrypted object storage
- WAF/DDoS controls
- centralized SIEM and alerting
- immutable/WORM audit retention
- disaster recovery and RPO/RTO validation
- independent penetration testing
- incident response and account recovery procedures
- legal/privacy requirements and, for financial milestones, applicable financial regulation and partner controls
