# Legacy Pulse V2 — Checkpoint V2.0-D: Legacy Release State Machine

Scope: **H2, H3**, deferred out of V2.0-B in the original audit because
they required a design change, not a same-shape bug fix. Full design
rationale in `docs/V2_0_D_PLAN.md`; this document is the "what was done
and how it was verified" report.

## Changes implemented

### H2 (High) — Non-transactional release side-effects
**New file:** `backend/src/services/legacyMessageRelease.js`
**Changed:** `backend/src/services/releaseScheduler.js`,
`backend/src/routes/trustedContacts.routes.js`

Both the cron sweep and the trusted-contact confirmation flow previously
ran their own inline sequence of statements (update status → look up
beneficiary → insert notification → log audit) with no transaction
wrapper. A crash between steps could leave a message marked `released`
with no notification ever sent.

`releaseMessage(messageId, trigger)` is now the **only** code path that
transitions a message from `pending` to `released`, wrapped in a single
`db.transaction()`. It's also idempotent — guarded by
`WHERE status = 'pending'` at update time — so calling it twice (from two
different trigger points, or a retried sweep) is a safe no-op the second
time rather than a duplicate release/notification.

### H3 (High) — Messages created after the confirmation threshold is already met never release
**Changed:** `backend/src/routes/legacyMessages.routes.js`

`attemptReleaseTrustedContactMessages(ownerId)` — which checks whether the
confirmation threshold is met and releases every matching pending
message — is now called from **two** places instead of one: the existing
confirm-submission trigger, and (new) immediately after creating a new
`trusted_contact_confirmation` message. If the threshold was already met
before the message existed, it releases on creation instead of sitting in
`pending` indefinitely.

## How this was verified

Not just "the code looks right" — three specific verifications:

1. **Forced-failure rollback test**: a regression test renames the
   `notifications` table out from under `releaseMessage()` mid-call (so
   the `INSERT` inside the transaction throws), then asserts the
   message's `status` is still `pending` and `released_at` is still
   `NULL` — proving the transaction actually rolled back the status
   update too, not just that the code happens to be wrapped in
   `db.transaction()`.
2. **Live-server H3 reproduction**: rather than trusting the test suite
   alone, I ran a full manual walkthrough against a real running server —
   registered 4 real accounts, linked a beneficiary and two trusted
   contacts, had both contacts confirm (2/2, threshold met) **before**
   creating any message, then created a new `trusted_contact_confirmation`
   message and confirmed via `curl` that the API response showed
   `"status": "released"` immediately. This is the exact scenario that was
   broken in V1/V2.0-B — it would have returned `"status": "pending"` and
   stayed that way forever.
3. **Sweep fault isolation test**: confirms that if releasing message A in
   a batch sweep were to fail, message B in the same sweep still releases
   correctly (each message's release is its own independent transaction,
   not one transaction wrapping the whole sweep).

## New tests

6 new tests in `v2d_h2_h3_release.test.js`:
- Forced mid-transaction failure → rollback verified → retry succeeds
- Idempotency: releasing an already-released message is a safe no-op, not
  a duplicate notification
- Sweep fault isolation across two messages
- **The H3 scenario itself**, end-to-end through the real API: confirm
  twice, then create → immediate release → beneficiary can read it
  right away
- Regression check: a message created *before* the threshold is met still
  correctly stays `pending` (proving the fix didn't break the normal case)
- `attemptReleaseTrustedContactMessages` is a safe no-op when the
  threshold isn't met

**Full suite: 90/90 passing** (84 from V2.0-C + 6 new).

## Database changes

**None.** This checkpoint is a pure logic/architecture change — no new
columns, no migration. The `legacy_messages`, `release_confirmations`, and
`notifications` tables are unchanged.

## What this checkpoint deliberately does not change

- The release **conditions** themselves (scheduled date; N-of-M trusted
  contact confirmations; immediate) are unchanged.
- Still **no distributed-lock/multi-process coordination**. The atomicity
  guarantee here is "a crash between statements within one process can't
  corrupt state," not "two server processes racing to release the same
  message can't both succeed." `better-sqlite3` is inherently
  single-process; a real multi-instance production deployment would need
  a networked database with row-level locking, or an explicit distributed
  lock. Flagged for V2.0-F alongside the database engine question
  generally (SQLite → Postgres).

## Exact commands to reproduce

```bash
cd backend
npm install
cp ../.env.example .env
npm run migrate
npm test   # expect 90/90 passing, including v2d_h2_h3_release.test.js
```

To manually re-verify the H3 fix against a live server (what was actually
run to validate this checkpoint):

```bash
npm start &
# Register an owner, a beneficiary, and two trusted-contact accounts via
# POST /api/auth/register (all requiring the X-Legacy-Pulse-Client: 1
# header per V2.0-B's CSRF fix). Link the beneficiary and both trusted
# contacts to the owner via POST /api/beneficiaries and
# POST /api/trusted-contacts + their /claim endpoints.
#
# Have BOTH trusted contacts confirm BEFORE creating any message:
curl -s -X POST http://localhost:4000/api/trusted-contacts/confirm/<ownerId> \
  -H "Authorization: Bearer <contact1Token>"
curl -s -X POST http://localhost:4000/api/trusted-contacts/confirm/<ownerId> \
  -H "Authorization: Bearer <contact2Token>"
# Expect the second response: {"confirmationsReceived":2,"confirmationsRequired":2}
#
# NOW create a new trusted_contact_confirmation message:
curl -s -X POST http://localhost:4000/api/legacy-messages \
  -H "Authorization: Bearer <ownerToken>" -H "Content-Type: application/json" \
  -d '{"beneficiaryId":<id>,"title":"Test","body":"Test","releaseType":"trusted_contact_confirmation"}'
# Expect the response to show "status": "released" immediately, NOT "pending".
```
