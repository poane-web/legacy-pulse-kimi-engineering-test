# Legacy Pulse V2 — Checkpoint V2.0-D: Legacy Release State Machine

Scope, per `docs/V2_SECURITY_AUDIT.md` §"Areas out of scope for V2 Phase
1": **H2, H3** — deliberately deferred out of V2.0-B because they need a
proper redesign, not a same-shape patch.

## Problem restated

- **H2:** release side-effects (mark message released, insert
  notification, and — for trusted-contact confirmations — count
  confirmations across potentially many messages) were spread across
  multiple non-transactional `better-sqlite3` statements. A crash between
  them could leave a message marked released with no notification ever
  sent, or (for the batch confirm-triggered release) some messages
  released and others not.
- **H3:** a `trusted_contact_confirmation` message created *after* the
  confirmation threshold for its owner was already met would sit in
  `pending` forever — release only happened at the moment the Nth
  confirmation arrived, scanning only messages that already existed at
  that moment. There was no re-check on message creation, and no periodic
  sweep for this release type (unlike `scheduled_date`, which the cron job
  re-scans every minute regardless of creation time).

## Design: a single, shared release module

New `backend/src/services/legacyMessageRelease.js` is now the **only**
code path that ever transitions a legacy message from `pending` to
`released`. Both the cron sweep (`releaseScheduler.js`) and the
trusted-contact confirmation flow (`trustedContacts.routes.js`) call into
it, instead of each maintaining their own inline release logic — this is
the actual "state machine" the checkpoint name refers to: one place owns
the `pending → released` transition and its invariants.

### `releaseMessage(messageId, trigger)`

Wrapped in a single `db.transaction()`: re-reads the message with
`WHERE status = 'pending'` (so a message already released by a concurrent
call is a no-op, not a double-release or duplicate notification — a
correctness guard, not just a performance one), flips its status,
inserts the notification, and writes the audit log entry, all atomically.
If any step throws, `better-sqlite3`'s transaction wrapper rolls back
**everything** — the message stays `pending`, ready to be correctly
retried on the next sweep/confirmation event, instead of ending up
half-released. This directly fixes **H2**.

**Verified, not just designed this way:** a regression test forces the
notification insert to fail mid-transaction (by temporarily renaming the
`notifications` table) and confirms the message's status is *not* changed
— proving the rollback actually happens, not just asserting the code
"should" be atomic because it's wrapped in `db.transaction()`.

### `attemptReleaseTrustedContactMessages(ownerId)`

Checks whether `ownerId` currently has enough confirmations
(`release_confirmations` count ≥ `config.requiredReleaseConfirmations`),
and if so, calls `releaseMessage()` for every currently-`pending`
`trusted_contact_confirmation` message belonging to that owner.

This function is now called from **two** places:
1. `trustedContacts.routes.js` `POST /confirm/:ownerId` — after recording
   a new confirmation (unchanged trigger point from V1/V2.0-B).
2. **New:** `legacyMessages.routes.js` `POST /` (create) — immediately
   after inserting a new `trusted_contact_confirmation`-type message. If
   the owner's confirmation threshold was already met *before* this
   message existed, it releases immediately instead of sitting in
   `pending` forever. This directly fixes **H3**.

Because `attemptReleaseTrustedContactMessages` and `releaseMessage` are
both idempotent (guarded by `WHERE status = 'pending'`), calling this
function defensively in more than one place is safe by construction, not
just "probably fine" — a message can't be released twice, and calling the
function when the threshold *isn't* met is a correct no-op.

### `attemptReleaseScheduledMessages()`

The same due-date scan `releaseScheduler.js` already had, now
implemented as repeated calls to `releaseMessage()` per due message
instead of one shared inline UPDATE — so a failure releasing message A
(e.g. a corrupt row) no longer prevents message B in the same sweep from
being correctly released; each message's release is its own transaction.

## What this checkpoint deliberately does NOT change

- The **release conditions themselves** (scheduled date; N-of-M trusted
  contact confirmations; immediate) are unchanged — this checkpoint fixes
  *how reliably* a release happens once its condition is met, not what
  the conditions are.
- Still **no distributed-lock/multi-process coordination** — the atomicity
  guarantee here is "a crash between statements can't corrupt state,"
  not "two server processes racing to release the same message can't
  both succeed." `better-sqlite3` is single-process by nature (a
  production multi-instance deployment would need a networked DB with
  real row-locking or an explicit distributed lock — a V2.0-F concern
  alongside the database engine question generally).
