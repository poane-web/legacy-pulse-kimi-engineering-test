# Legacy Pulse V6 — Outbox Red-Team Baseline

## Target

Branch: `chatgpt-v6-outbox-hardening`

Baseline: ChatGPT temporal-hardening commit `06bc126fd16da57cf54c3c954b64061633fdf4f3`

Attack-test commit: `2f5967cab037e0bc1ae10e0d5196d4c795084cf3`

## Scope

This pass attacks the boundary:

`release transaction -> durable delivery intent -> publisher -> external notification provider`

Previous scheduler logic currently commits the release, recipient snapshot, database notification and audit record in one SQLite transaction. The implementation does **not** currently contain a durable `outbox_events` table or an independent outbox publisher.

That distinction matters: a database notification row is not proof that an external notification provider received a delivery instruction.

## Attack-first findings

### V6-O1 — No durable outbox event

**Severity: HIGH**

A released message has no durable event representing the external delivery intent. A process crash after the release transaction means there is no independent work item for a publisher to recover.

The new adversarial test requires `outbox_events` and therefore fails against the current baseline.

### V6-O2 — No publisher lease / retry state

**Severity: HIGH**

There is currently no durable publisher state containing attempt count, lease ownership, retry timing or a stale-worker fencing token.

### V6-O3 — No stable external-delivery idempotency key

**Severity: HIGH**

The current implementation has no event-level idempotency key that can safely be reused when a provider accepts a request but the response is lost.

### V6-O4 — Exactly-once external delivery is not established

**Severity: HIGH**

The current CAS protection establishes a database release transition, but it does not establish exactly-once delivery to an external provider. Those are separate guarantees.

## Required V6 invariant

For every committed release there must be exactly one durable delivery intent:

`legacy-message:<message-id>:released`

with a database-enforced uniqueness constraint.

The publisher must process that intent with lease/fencing semantics and an idempotency key. Provider delivery must be treated as at-least-once unless the external provider itself provides stronger guarantees.

## Failure cases to prove

1. release commits and process crashes before publisher runs;
2. publisher claims and crashes;
3. lease expires and another publisher claims;
4. provider accepts request but response is lost;
5. provider times out and publisher retries;
6. two publishers race on the same event;
7. provider returns 429/5xx;
8. provider is unavailable for an extended period;
9. release is retried;
10. stale publisher resumes after another worker has completed delivery.

## Current status

**No production remediation has been applied in this pass.**

The purpose of this commit is to establish failing adversarial tests before implementation changes, so the eventual green result demonstrates that the root cause was actually removed rather than that the tests were written around the implementation.
