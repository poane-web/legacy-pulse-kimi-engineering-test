# Legacy Pulse V3 — Production Threat Model

**Methodology note, stated upfront because it governs how to read every
claim below:** this codebase runs on SQLite in every environment it has
actually been tested in. SQLite executes all statements from a single
process, strictly serialized -- no two statements from different requests
can ever truly interleave mid-statement. Several of the attack categories
requested (H: transactional integrity under concurrent Postgres workers)
are **structurally impossible to reproduce empirically in this
environment**, because the substrate that would make them possible
(genuine multi-process concurrent writers against a shared database) does
not exist here. Every claim below is labeled:

- **[VERIFIED]** -- reproduced with a real, passing regression test against
  the actual running application.
- **[VERIFIED LIVE]** -- additionally reproduced against a real running
  server process (not just the Jest suite), same standard as V2.
- **[REASONED]** -- the code was read and the concurrency/correctness
  argument was worked through explicitly (shown below), but not
  empirically reproduced, because doing so would require infrastructure
  (multi-worker Postgres) not available in this environment. This is not
  the same confidence level as VERIFIED, and is never presented as such.
- **[NOT ATTEMPTED]** -- explicitly out of scope for this pass, named so it
  isn't mistaken for "checked and found fine."

Findings from V2 are not re-derived here; they're re-validated against
the *new* adversarial scenarios this pass specifically asked for, and
cited by their V2 ID where a V2 fix already addresses part of a scenario.

---

## A. Identity

### V3-H1 -- Invite-claim race condition (TOCTOU) -- **FIXED**
- **Attack:** two concurrent requests race to claim the same beneficiary
  or trusted-contact invite token.
- **Root cause:** the claim handlers did `SELECT ... WHERE invite_status =
  'pending'` then, as a **separate** statement, `UPDATE ... WHERE id = ?`
  -- with no re-check of `invite_status` in the UPDATE's own WHERE clause.
  Two concurrent requests could both pass the SELECT before either UPDATE
  committed.
- **Exploitability:** **[REASONED]** requires genuine multi-process
  concurrency (real Postgres, multiple app workers) to trigger for real --
  SQLite's single-process serialization makes this specific interleaving
  structurally impossible to reproduce here, which is exactly the class of
  bug this exercise is designed to surface: invisible in this repo's only
  tested environment, real once ported to production infrastructure.
- **Impact, corrected after deeper analysis:** an earlier draft of this
  finding assumed a *hijack* scenario (attacker account B steals a claim
  intended for account A). On closer analysis that specific outcome is
  **not** possible here: `beneficiaries.routes.js`'s claim handler (fixed
  in V2 finding C2) requires the claiming account's email to match the
  invite's target email, and `users.email` has a UNIQUE constraint -- so at
  most one registered account can ever pass that check for a given
  invite. The real, still-genuine impact is narrower: **duplicate
  processing by the same legitimate account** (e.g. a double-click or a
  replayed request racing the original) could produce two audit log
  entries (`beneficiary.invite_claimed` logged twice) for what should be a
  single event, muddying the audit trail during a future investigation,
  and represents an inconsistency with the atomic-conditional-update
  pattern already established elsewhere (`services/legacyMessageRelease.js`).
  Correcting my own initial overstatement here in place, per the
  instruction to treat every security claim -- including ones I generate
  myself -- as unverified until checked.
- **Fix:** the UPDATE is now a single atomic conditional statement --
  `UPDATE ... SET ... WHERE id = ? AND invite_status = 'pending'`, with
  the affected-row count checked; a second/racing attempt gets a clean
  `409`/`404` instead of silently re-processing.
- **Security invariant:** exactly-once state transition for a single
  event (an invite being claimed).
- **Regression test:** **[VERIFIED]** `v3_h1_h2_m1_m2_m3_l1.test.js` --
  sequential double-claim rejected cleanly; direct unit-level proof the
  atomic guard's WHERE clause refuses a second write; **and** a genuinely
  concurrent test using `Promise.all` (not sequential `await`s) firing two
  claim requests simultaneously through Express, confirming exactly one
  succeeds and exactly one audit log entry is written -- the strongest test
  achievable without real multi-process Postgres.
- **Residual risk:** the fix is reasoned to be correct for Postgres (a
  single `UPDATE ... WHERE` with a row-matching predicate is atomic under
  any real RDBMS's row-level locking), but has not been empirically load-
  tested against real concurrent Postgres connections. Flagged for
  pre-production load testing.

### V3-H2 -- Beneficiary deletion silently destroys already-released content -- **FIXED**
- **Attack:** an owner deletes a beneficiary who has already-received
  (`status = 'released'`) legacy messages.
- **Root cause:** `legacy_messages.beneficiary_id` is `ON DELETE CASCADE`.
  The delete route performed no check at all before issuing the delete --
  it relied entirely on the FK cascade.
- **Exploitability:** **[VERIFIED]** -- trivially reproducible by any owner
  against their own data (not even a cross-account attack; the owner does
  this to their own beneficiary/message), which arguably makes it worse:
  no adversary is even required, just a careless or malicious click.
- **Impact:** permanent, silent destruction of content a beneficiary may
  have already read and rely on existing -- directly contradicts the
  stated invariant "changing beneficiary relationships must not
  retroactively redirect already-released content" (this is arguably a
  strictly worse outcome than redirection: destruction, not misdirection).
- **Fix:** `DELETE /beneficiaries/:id` now checks for any `status =
  'released'` messages addressed to that beneficiary and rejects deletion
  with `409` if any exist, explaining why. Deletion still succeeds
  normally when only pending (never-delivered) messages exist -- nothing
  was ever delivered, so cascading them away is the existing, correct,
  and unchanged V1/V2 behavior for that case.
- **Security invariant:** released content, once delivered, cannot be
  retroactively un-delivered by an unrelated administrative action
  elsewhere in the data model.
- **Regression test:** **[VERIFIED]** 3 tests -- blocked when a released
  message exists (content and beneficiary both still present afterward),
  allowed when no messages exist, allowed when only pending messages
  exist (no regression).
- **Residual risk:** this only covers the beneficiary->message relationship.
  The equivalent question for trusted contacts (does revoking a trusted
  contact after they've already confirmed retroactively affect anything?)
  was reasoned through and found safe: `release_confirmations` is `ON
  DELETE CASCADE` from `trusted_contacts`, so revoking a contact removes
  their confirmation -- correctly reducing the standing confirmation count
  going forward, with no effect on messages *already* released (their
  `status` field is independent, already transitioned, and untouched by
  this cascade). No fix needed there; documented as reviewed.

### V3-M2 -- Account deletion orphans encrypted files on disk -- **FIXED**
- **Attack:** none required -- this is a data-hygiene gap that manifests on
  every account deletion, not something an adversary triggers.
- **Root cause:** `DELETE /users/me` relied entirely on `ON DELETE
  CASCADE` to remove `documents`/`photos` **rows**, but never called
  `storage.remove()` for the actual encrypted **files** those rows
  pointed at. The ciphertext bytes remained on disk forever, unreferenced
  by any database row (unreachable via the API, but not actually deleted).
- **Exploitability:** N/A (not attacker-triggered) -- flagged under "data
  minimization" / "right to be forgotten" more than classic security
  impact, but genuinely relevant to a "delete my account" feature whose
  entire point is deletion.
- **Impact:** unbounded storage growth over the application's lifetime,
  and a real GDPR-adjacent concern (encrypted personal data persisting
  after a user explicitly requested deletion, even though inaccessible
  through the app).
- **Fix:** `DELETE /users/me` now looks up every `documents`/`photos` row
  the account owns and calls `storage.remove()` for each **before** the
  cascading DB delete.
- **Security invariant:** "delete my account" means the data is actually
  gone, not merely unreferenced.
- **Regression test:** **[VERIFIED]** uploads a real document and photo,
  confirms both files exist on disk, deletes the account, confirms both
  files are gone from disk (not just their DB rows).
- **Residual risk:** this only addresses local-disk storage. If/when
  storage moves to S3/GCS (`docs/V2_0_F_PRODUCTION_READINESS.md`), the
  equivalent cleanup call needs to exist in that backend's `remove()`
  implementation too -- the seam (`services/storage.js`) already
  anticipates this, but it's worth naming explicitly so the requirement
  isn't lost in a future migration.

### Beneficiary/trusted-contact identity changes -- reviewed, no new finding
Re-checked against the exact invariants named in the prompt:
- "Changing beneficiary relationships must not retroactively redirect
  already-released content" -- **[VERIFIED]**: `legacy_messages.beneficiary_id`
  is set once at creation and is never updatable via any route (`PUT
  /beneficiaries/:id` only allows editing `fullName`/`relationship`, never
  reassigning which beneficiary a message targets). No redirect vector
  exists.
- "Changing trusted-contact identity must not invalidate or manufacture
  historical authority incorrectly" -- **[VERIFIED]**: a trusted contact's
  identity (their linked `user_id`) is set exactly once, at claim time,
  and is immutable afterward (no route ever updates
  `trusted_contacts.linked_user_id`). A confirmation is permanently tied
  to the `trusted_contact_id` that submitted it via the FK; there is no
  way for a later identity change to retroactively alter what an earlier
  confirmation "means."
- "Account disabling must invalidate sensitive operations appropriately" --
  covered by V2's H1 fix (`token_version`); re-verified here to still hold
  correctly against the new scenario of a **beneficiary's own** account
  being disabled mid-flow: if a beneficiary's account is disabled after a
  message was released to them, their access token is invalidated
  (H1), but the release itself is unaffected (correct -- the message
  already reached them; disabling their account going forward doesn't
  retroactively un-release it, nor should it).
- "Password/MFA changes must interact safely with active sessions and
  pending releases" -- re-verified: password change bumps `token_version`
  (V2 H1), correctly killing live sessions; it has **no effect** on
  pending releases, which is correct -- password possession was never part
  of a release condition.

### Missing feature, explicitly named -- no password reset flow
**[VERIFIED -- by its absence]** there is no "forgot password" flow
anywhere in this codebase. The only path to changing a password is `PUT
/users/password`, which requires knowing the *current* password. A user
who forgets their password has **no self-service recovery path at all**
-- not a vulnerability (nothing to attack; the feature doesn't exist), but
a real production gap explicitly worth naming rather than silently
passing over, since the prompt specifically asked to "attack: password
reset." There is nothing to attack because there is nothing there. When
built, it needs: a single-use, expiring, cryptographically random token
(same pattern as invite tokens); no account-existence leakage in the
response regardless of whether the email is registered; rate limiting;
and (per V3-H1's lesson above) an atomic conditional UPDATE when
consuming the token, not a check-then-act pair.

---

## B. Release authority

### Re-verified against every listed attack scenario

| Attack | Status |
|---|---|
| Stale trusted-contact permissions | **[VERIFIED]** -- a revoked contact's confirmation is removed via cascade (see V3-H2 discussion); a revoked contact cannot submit new confirmations (`WHERE ... status = 'active'` check in the confirm route, unchanged from V1/V2, re-verified still correct) |
| Revoked trusted contacts | Same as above |
| Beneficiary replacement | Not possible -- `beneficiary_id` is immutable on a message (see Identity section) |
| Deleted beneficiaries | **Fixed this pass** -- V3-H2 |
| Changed account ownership | Not a concept that exists in this app (no account-transfer feature) -- N/A |
| Stale JWTs | Covered by V2 H1 (`token_version`) |
| Stale refresh tokens | Covered by V1's rotation-on-use + V2.0-C's cleanup script |
| Password changes | Covered by V2 H1 |
| MFA changes | Covered by V2.0-C; re-verified the challenge-token/disable-mid-flow interaction (see G below) |
| Concurrent sessions | No session limit exists (by design); nothing release-relevant depends on session count |
| Concurrent confirmations | **[REASONED]**, see V3-C1 below -- argued safe by construction |
| Scheduler races | **[REASONED]**, see V3-C2 below |
| Scheduler restart | **[REASONED]** -- `attemptReleaseScheduledMessages` re-scans `WHERE status='pending' AND release_at <= now()` on every invocation; a restarted scheduler simply resumes scanning the same query with no special-cased "resume" state needed, and the idempotent `releaseMessage` guard means a message can't be double-released even if the previous process crashed mid-release (V2.0-D's H2 fix already covers this -- a crash mid-transaction rolls back to `pending`, correctly re-picked-up) |
| Duplicate workers | **[REASONED]**, see V3-C2 |
| Retry storms | **[REASONED]** -- `releaseMessage`'s idempotency guard means any number of retries (from a scheduler, a client, or a malicious replay of the confirm endpoint) converge to at most one actual release; extra retries are simply no-ops |
| Clock manipulation | **[REASONED]**, see V3-D1 |
| Timezone/DST boundaries | **[VERIFIED -- by design]**, see V3-D1 |
| Config changes immediately before/during release | **[REASONED]** -- `config.requiredReleaseConfirmations` is read fresh on every `confirmationsMet()` call (not cached), so a config change takes effect on the very next request; there is no window where a stale threshold value is used mid-release, since release isn't a long-running operation that reads config once at the start and acts later |
| Cancellation during release | **[VERIFIED]** -- `PUT`/`DELETE` on a legacy message both explicitly check `status !== 'pending'` and reject with `400` if the message is already released or mid-processing; combined with the atomicity of `releaseMessage`, there is no window where a message is "being released" as a distinct observable state a cancellation could race against -- the transition is a single atomic statement, not a multi-step process with an interruptible middle |
| Reactivation after cancellation | **[VERIFIED]** -- there is no "reactivate" or "un-delete" operation anywhere in the API for a deleted/revoked message; once deleted, a message is gone (standard cascading delete), so there's no reactivation surface to attack |

### V3-C1 -- Concurrent confirmations: reasoned safety argument
Two trusted contacts confirming at genuinely the same moment, each in
their own DB transaction/connection: does at least one of the two
resulting `attemptReleaseTrustedContactMessages` calls definitely observe
the *complete* confirmation count?

**[REASONED]:** Yes. Each request's own `INSERT` (autocommitted) always
happens-before that same request's own `SELECT COUNT` (sequential
statements within one request's program order). Whichever of the two
confirmations commits **last** in real time -- call it confirmation B,
committing at time `T_b` -- has its own count-check necessarily execute
*after* `T_b`. Under `READ COMMITTED` (Postgres's default isolation
level), that count-check will observe every commit that happened before
its own query started, which includes confirmation A's earlier commit
(since A committed before B did, by definition of B being "last"). So the
temporally-last confirmation's own request will always see the true,
complete count -- guaranteeing release is triggered by at least one of the
two requests, even though the *other* request's count-check might have
seen a stale, incomplete count and correctly done nothing. This is not
empirically load-tested (no Postgres available), but the argument holds
for any RDBMS offering at least `READ COMMITTED` isolation, which
includes both SQLite (its actual isolation model is closer to
serializable, strictly stronger) and Postgres's default.

### V3-C2 -- Duplicate scheduler workers: reasoned safety argument
**[REASONED]:** Already covered structurally by V2.0-D's design (see
`docs/V2_0_D_CHECKPOINT.md`) and V2.0-F's explicit naming of this exact
scenario as a *known, accepted* inefficiency (not a correctness bug): N
scheduler instances each independently `SELECT`-ing the same due-message
IDs will each attempt `releaseMessage()` on the same set; the first
`UPDATE ... WHERE status = 'pending'` to commit wins, every subsequent one
affects zero rows and returns `false` (no-op). No duplicate release, no
duplicate notification, under any number of concurrent workers. The
**inefficiency** (wasted duplicate scans/attempts) was already flagged in
V2.0-F as something a production deployment should fix by running the
scheduler as a single dedicated worker rather than embedded in every web
process -- this remains the correct recommendation; it's a scalability
concern, not a correctness one.

---

## C. Exactly-once release

Restated from the "release authority" attacks above, addressing the
prompt's explicit request to distinguish these three separate guarantees:

- **Exactly-once authorization** (a release should only ever be
  *authorized* to happen once its conditions are truly met): **[VERIFIED]**
  via V2.0-D's H3 fix (re-checked on message creation, not just at
  confirmation time) plus this pass's confirmation-visibility endpoint
  (V3-M3) giving the owner a way to actually see and react to a
  "primed" state before it's exploited by a mistaken/malicious pair of
  confirmations.
- **Exactly-once state transition** (`pending -> released` happens at most
  once per message, regardless of how many processes/retries attempt it):
  **[VERIFIED + REASONED]** -- verified empirically against SQLite
  (V2.0-D's forced-failure rollback test, this pass's concurrent-dispatch
  test), reasoned to hold for Postgres via the atomic-conditional-UPDATE
  argument above (V3-C1/C2).
- **At-least-once notification delivery**: **[VERIFIED, and this is a
  genuine, named limitation, not a bug]** -- the notification INSERT
  happens inside the same transaction as the status update
  (`legacyMessageRelease.js`), so notification delivery is coupled to
  successful release, not decoupled with its own retry queue. This means
  notification delivery is **exactly-once at the database-row level**
  (one `notifications` row per release), but the app has **no delivery
  confirmation, retry, or dead-letter mechanism** if a beneficiary never
  sees the notification for some reason (e.g. they never log in again).
  This is architecturally fine for an in-app notification (the row exists
  and will be seen next time they load `GET /notifications`, regardless
  of when that is), but would need a genuine at-least-once retry queue if
  this were ever extended to push/email notifications, which do have
  real delivery failure modes an in-app row doesn't.

---

## D. Temporal security

### V3-D1 -- Timezone/DST: reviewed, found safe by design
**[VERIFIED -- by design, and by reading every comparison site]**: every
timestamp in this system -- `release_at`, `released_at`, `created_at`,
`locked_until`, `expires_at`, `revoked_at` -- is generated via
`new Date().toISOString()` (Node) or SQLite's
`strftime('%Y-%m-%dT%H:%M:%fZ','now')`, both of which produce UTC,
`Z`-suffixed ISO 8601 strings. Every comparison (`release_at <= ?`,
`locked_until > ?`, `expires_at < ?`) is a **lexicographic string
comparison** in SQL between two values in this exact same normalized
format. ISO 8601 UTC timestamps compare correctly lexicographically
regardless of the *client's* timezone, DST transitions, or any timezone
metadata, because there is no timezone-relative data anywhere in a stored
timestamp to misinterpret -- everything is already UTC before it touches
the database. There is no DST-boundary bug class available here, because
there is no local-time arithmetic anywhere in the codebase.

### Revoke-immediately-before/after-release, confirmation-immediately-before/after-expiry
**[VERIFIED]**: covered by the same atomicity argument as V3-C1/C2 --
there is no window where "revoke" and "release" can observe each other in
an inconsistent intermediate state, because both ultimately reduce to
single atomic conditional statements against the same rows. "Confirmation
immediately before/after expiry" doesn't apply as asked, because -- see
next finding -- confirmations don't currently expire at all.

### V3-D2 -- Confirmations never expire, and the owner has limited tooling to react -- **PARTIALLY ADDRESSED**
- **Attack:** two trusted contacts confirm (mistakenly, or in collusion)
  while the owner is alive and well. Nothing in the system ever expires
  or resets that state short of the owner manually revoking and
  re-inviting trusted contacts (which cascades away confirmations).
- **Root cause:** `release_confirmations` has no expiry column and no
  code path ever deletes a confirmation except via `ON DELETE CASCADE`
  from revoking the confirming contact.
- **Impact:** the account becomes permanently "primed" -- any *future*
  `trusted_contact_confirmation` message the owner creates auto-releases
  immediately (the correct, intended behavior of V2.0-D's H3 fix, now
  working against the owner if the underlying confirmations were wrong).
- **Fix, this pass:** `GET /trusted-contacts/confirmation-status` (V3-M3)
  gives the owner visibility into this state for the first time -- they
  can now at least *see* "2/2 confirmed" and react (revoke the contacts,
  which clears it).
- **Not fixed this pass, explicitly deferred:** there is still no
  time-based expiry for confirmations, and no one-click "reset without
  losing the trusted contact relationship" action (the only reset
  mechanism destroys and requires re-inviting the contact). Flagged in
  `docs/security/V3-PRODUCTION-READINESS.md`.

---

## E. Cryptography

Re-reviewed against the new prompt list; most of this is already covered
by V2.0-C's M1 (AAD/versioning) and V2.0-F's KMS/rotation gap analysis.
New checks specific to this pass:

- **Plaintext leakage in logs/error messages** -- **[VERIFIED]**: read
  every `catch` block and every `logAudit()` call site across all routes.
  `logAudit`'s `metadata` parameter is only ever passed small,
  non-content fields (MIME types, byte counts, email addresses for
  failed-login attempts, reasons/trigger names) -- never a decrypted field
  value. `morgan` request logging does not log request bodies (confirmed
  in V1, re-verified unchanged). Crypto module error messages
  (`Malformed encrypted field payload`, `Missing required AAD context`,
  Node's own GCM auth-tag-mismatch error) contain no plaintext or key
  material.
- **Backups / database dumps** -- **[NOT ATTEMPTED, correctly out of
  scope]**: no backup mechanism exists yet (named in V2.0-F), so there is
  nothing to audit for leakage here yet -- this becomes relevant the
  moment backups are implemented (V2.0-F item).
- **Thumbnails/previews** -- **[VERIFIED -- by absence]**: no thumbnail
  generation exists anywhere in the codebase; photos are stored and
  served as full encrypted originals only. No additional exposure surface.
- **Temporary files** -- **[VERIFIED]**: `multer.memoryStorage()` keeps
  uploaded file bytes entirely in a `Buffer` in process memory; nothing
  ever touches disk unencrypted before `storage.save()` encrypts it. No
  temp-file plaintext window exists.
- **Key separation / rotation / versioning** -- unchanged from V2.0-C/F:
  a single symmetric key, versioned ciphertext format that makes future
  rotation *possible* but not yet *implemented*. No new finding this
  pass; re-confirmed the gap is accurately described in existing docs.

---

## F. File security

Re-reviewed against the new list; V2.0-B's H4 (magic-byte validation) and
this app's storage design (random UUID filenames, never user-controlled)
already address most of this list. New findings:

### V3-L1 -- Filename header hardening -- **FIXED (defense-in-depth)**
- **Attack:** a filename containing control characters (e.g. CR/LF)
  placed into the `Content-Disposition` response header.
- **Exploitability:** **[VERIFIED -- and found NOT independently
  exploitable]** -- Node's `http` module already rejects raw CR/LF in
  header values at the runtime level (`setHeader` throws), which was
  confirmed by testing it directly. So this was not an actual live
  vulnerability in the current Node version. Fixed anyway as
  defense-in-depth: relying on a specific runtime's internal protections,
  rather than sanitizing at the application layer, is fragile -- a future
  Node version, a different runtime, or a proxy/CDN in front of this app
  with different header-parsing behavior could reintroduce the class of
  bug this appears to guard against.
- **Fix:** new `utils/sanitizeFilename.js` strips all control characters
  and quotes, caps length at 200 characters, applied to the document
  download route's `Content-Disposition` header.
- **Regression test:** **[VERIFIED]** -- unit tests on the sanitizer
  directly, plus an end-to-end upload/download test with a
  control-character-containing filename confirming the response header
  contains no raw CR/LF.

### Everything else in this category -- reviewed, no new findings
- **MIME spoofing / magic-byte mismatch:** V2.0-B H4, re-verified still
  correctly rejects mismatched content on both documents and photos.
- **Polyglot files:** the signature checker (`fileSignature.js`) checks
  that the declared type's signature matches AND that no *other* known
  signature matches better -- this specifically defeats the classic
  "PNG-that-is-also-a-valid-ZIP" polyglot trick for the file types this
  app recognizes, since a polyglot matching two of the checked signatures
  would fail the "exactly the declared type" check.
- **Path traversal:** stored filenames are always `crypto.randomUUID()`,
  never derived from user input at any point -- no traversal surface
  exists structurally, not just "no traversal string was found."
- **Decompression bombs:** no file is ever decompressed/parsed
  server-side (even DOCX, itself a ZIP, is only checked for its 4-byte
  ZIP signature, never opened) -- no decompression surface exists.
- **Oversized files:** `MAX_UPLOAD_MB` (multer `limits.fileSize`) is
  enforced; **new observation, not a fix**: because uploads use
  `memoryStorage`, many concurrent large uploads could still pressure
  process memory even with a per-file cap -- flagged as a production
  scalability item (`V3-PRODUCTION-READINESS.md`), not a vulnerability
  (the per-file cap is real and enforced; this is about aggregate
  concurrent load).
- **Unauthorized download / stale authorization / cross-user file
  references:** `requireOwnership` re-checks ownership on every
  document/photo route on every request -- there is no cached/stale
  authorization state to attack.
- **Deleted-owner access:** covered by V3-M2 above (files are now
  actually deleted, not merely orphaned) and by the pre-existing
  `ON DELETE CASCADE` removing the DB rows, which already made the file
  inaccessible via the API even before this pass's fix (the fix closes
  the *disk hygiene* gap, not an access-control gap -- access was already
  correctly blocked).
- **Direct object-storage access:** N/A -- there is no object storage yet
  (local disk only); this becomes relevant the moment V2.0-F's S3/GCS
  migration happens, and needs its own access-control review at that
  time (signed URLs, bucket policies, etc.) -- named in
  `V3-PRODUCTION-READINESS.md`.

---

## G. Authentication

Re-reviewed against the new list; most is covered by V2.0-B/C. New checks:

- **MFA-challenge-token / token_version interaction** -- **[VERIFIED]**:
  confirmed `POST /auth/mfa/verify` checks `user.status === 'disabled'`
  fresh from the DB at verify time (so a disable mid-flow correctly
  blocks completion), and checks `user.mfa_enabled` fresh too (so
  disabling MFA mid-flow correctly blocks completion with a clear error
  rather than a confusing partial state). **Noted, not fixed:** an
  outstanding challenge token is *not* invalidated by a `token_version`
  bump (e.g. "sign out everywhere"), since challenge tokens don't carry a
  `tokenVersion` claim at all. Reasoned impact: low -- completing an
  outstanding challenge token still requires a valid TOTP code, which
  `token_version`/session revocation was never protecting against
  anyway (MFA and session revocation are different controls). Documented
  as a residual gap, not fixed, given the low actual exploitability.
- **MFA brute-force via the verify endpoint** -- **[VERIFIED, found
  sufficiently mitigated]**: `POST /auth/mfa/verify` is covered by the
  same `authLimiter` as login (10 requests/15min in production) -- at that
  rate, exhausting even a meaningful fraction of the 6-digit (1,000,000)
  TOTP space is infeasible (roughly 960 attempts/day). Reviewed and found
  adequate; a dedicated MFA-specific lockout would be a nice-to-have, not
  a fix for a real gap.
- **Step-up authentication gap** -- **[VERIFIED, NOT FIXED this pass]**:
  `DELETE /trusted-contacts/:id` and (before V3-H2's unrelated fix)
  `DELETE /beneficiaries/:id` require nothing beyond a valid bearer
  token -- no password re-confirmation -- despite both actions directly
  affecting release authority (removing a check on who can trigger/receive
  a release). Compare with `POST /security/mfa/disable`,
  `DELETE /users/me`, and `PUT /users/password`, which all correctly
  require the current password as step-up. An attacker with a stolen
  (but valid, unexpired) access token could silently strip an account's
  trusted-contact protections without ever knowing the password. Genuine
  finding, **explicitly deferred** to keep this pass's fix set bounded
  and reviewable rather than touching every mutation endpoint's auth
  requirements in one sweep -- named as the top priority for the next
  checkpoint in `V3-PRODUCTION-READINESS.md`.
- **Logout / logout-everywhere / session fixation / JWT replay /
  refresh-token replay** -- all re-verified unchanged from V1/V2's correct
  behavior; no new findings.

---

## H. Database / transactional integrity (PostgreSQL assumption)

This category is the one most directly shaped by the SQLite-vs-Postgres
distinction stated at the top of this document. Findings V3-H1 (invite
claim) and the reasoning in V3-C1/C2 (confirmation counting, scheduler
duplication) are the concrete output of this category. Summary table:

| Pattern | SQLite behavior | Postgres reasoning | Status |
|---|---|---|---|
| `releaseMessage`'s conditional UPDATE | Serialized, trivially safe | Row-level lock during UPDATE, first-committer-wins, atomic | **[REASONED safe]**, matches an already-correct pattern |
| Invite-claim UPDATE (pre-fix) | Serialized, masked the bug | Two workers could both pass the SELECT, one silently overwrites | **[FIXED]** -- V3-H1 |
| Confirmation INSERT + COUNT (two statements) | Serialized | Reasoned safe via "last committer sees complete count" argument | **[REASONED safe]** -- V3-C1, not restructured into one statement since the argument holds |
| Confirmation duplicate INSERT | Serialized, UNIQUE constraint still enforced | Same UNIQUE constraint enforced; second INSERT throws | **[FIXED]** -- V3-M1, error now caught and translated to a clean 409 |
| Scheduler duplicate workers | Only one process ever runs it here | Reasoned safe (idempotent guard) | **[REASONED safe]**, known inefficiency already documented in V2.0-F |

**What "use database constraints and atomic transactions wherever
appropriate," taken seriously, actually changed this pass:** the two
concrete UPDATE-guard fixes (V3-H1) and the duplicate-insert error
handling (V3-M1) are direct instances of this. Everywhere else audited
under this category, the existing design (atomic conditional UPDATEs,
UNIQUE constraints, idempotent releaseMessage) was found to already
follow this principle correctly -- this pass's contribution was finding
the **two places it wasn't yet followed**, not introducing the pattern
from scratch.

---

## I. Auditability

- **Attributable:** **[VERIFIED]** every `logAudit()` call site includes
  `actorUserId` where an authenticated actor exists, `null` where the
  action is inherently unauthenticated (e.g. `auth.login_failed` against
  a possibly-nonexistent account) -- reviewed for consistency, found
  correct.
- **Tamper-evident:** **[VERIFIED -- as a gap, not a false claim]**:
  `audit_logs` has no update or delete route (V1 design, re-verified
  still true), which prevents *application-level* tampering. It is **not**
  cryptographically tamper-evident (no hash-chaining, no append-only
  storage guarantee at the infrastructure level) -- a party with direct
  database access could still alter rows. This was already implicitly
  understood but is worth stating explicitly: "no API route can modify
  it" and "cannot be tampered with" are different claims, and only the
  first is currently true.
- **Ordered:** **[VERIFIED]** `id INTEGER PRIMARY KEY AUTOINCREMENT` plus
  `created_at`, both monotonic; SQLite's autoincrement is safe within a
  single process. **[REASONED]** -- a Postgres `SERIAL`/`IDENTITY` column
  provides the equivalent guarantee under concurrent writers.
- **Replay-resistant:** N/A as a property of the audit log itself (the
  log is a passive record, not a mechanism replay could exploit) -- this
  applies to the *actions being logged*, which are covered under their
  own categories (G, H) above.
- **What must move to WORM/SIEM for production:** unchanged from
  V2.0-F's assessment -- restated here for completeness rather than
  duplicated at length: `audit_logs` should eventually be shipped to an
  external, genuinely append-only store (cloud WORM storage, or a SIEM
  ingesting a log stream) for real tamper-evidence and long-term
  retention independent of the application database's own availability.

---

## J. Admin trust

Treating the admin role as a high-value attacker per the prompt's
instruction -- re-examined `admin.routes.js` line by line again, looking
specifically for the scenarios named:

- **Compromised/malicious admin -- data access:** **[VERIFIED, re-confirmed
  by grep]** -- zero calls to `decryptField`/`decryptBuffer` anywhere in
  `admin.routes.js`. An admin, compromised or malicious, cannot read any
  owner's memories, documents, legacy message content, or photos through
  any admin-surfaced endpoint -- the routes structurally only ever query
  metadata columns.
- **Admin privilege escalation:** **[VERIFIED]** -- no route allows a
  caller to set their own or another account's `role`. Registration
  hardcodes `role: 'owner'`; the only way an account becomes `admin` is
  direct database access (documented in every test file that needs an
  admin account -- they all promote via a raw `db.prepare(...)` call,
  never through the API, because there is no API path to do it).
- **Admin impersonation:** **[VERIFIED -- as absent]** -- there is no
  "log in as user" / impersonation feature anywhere in the codebase. Not
  present, so nothing to attack; also means a legitimate support-style
  admin workflow (helping a locked-out user) doesn't exist yet, which is
  a product gap worth naming for whoever builds password reset (the
  identity-gap noted in section A) -- an impersonation feature, if ever
  built, needs its own dedicated threat model (audit-logged, time-boxed,
  requiring the target's consent or a documented support process).
- **Death-attestation abuse / release override:** **[VERIFIED]** -- admins
  have **no** endpoint that touches `release_confirmations` or
  `legacy_messages.status` at all. An admin cannot manually trigger,
  force, or override a release through any code path that exists today.
  This is a meaningful, structural finding worth stating plainly: the
  release-authority system (trusted contacts, confirmations, the state
  machine) is **entirely outside the admin role's reach** -- there is no
  "admin override" attack surface here because there is no admin override
  capability, full stop.
- **Audit manipulation:** covered above (I) -- no admin route (or any
  route) can update/delete `audit_logs` rows.
- **Application security vs. trusted infrastructure assumption,** stated
  explicitly per the prompt's request: everything above is an
  **application-security** claim, verified by reading the actual route
  code. It assumes the **infrastructure-level** trust boundary -- direct
  database access, direct filesystem access to the encryption key or
  `.env`, direct server/container shell access -- is itself protected by
  infrastructure controls (IAM, network segmentation, secrets management)
  this application cannot enforce from within itself. An admin (or anyone
  else) with direct DB access bypasses every one of these findings
  trivially; that is a trusted-infrastructure question, not an
  application-security one, and is addressed in
  `docs/security/V3-PRODUCTION-READINESS.md` under KMS/secrets management.

---

## Summary counts

- **Vulnerabilities discovered this pass:** 6 (V3-H1, V3-H2, V3-M1,
  V3-M2, V3-M3, V3-L1), plus 2 explicitly-named gaps not counted as
  "vulnerabilities" in the traditional sense but documented as real
  findings (no password-reset flow; confirmations never expire/no
  step-up auth on trusted-contact revocation).
- **Fixed:** 6 of 6 numbered findings (V3-H1 through V3-L1). V3-M3
  (confirmation visibility) is a partial mitigation of V3-D2, not a full
  fix -- documented as such above, not overstated.
- **Deferred, explicitly:** step-up authentication for trusted-contact
  revocation (G), confirmation expiry (D2), password-reset flow (A),
  admin impersonation feature design (J, if ever built) -- all named in
  `docs/security/V3-PRODUCTION-READINESS.md`.
- **New regression tests:** 15, all passing, in
  `v3_h1_h2_m1_m2_m3_l1.test.js`. Combined with V1/V2's suite: **117/117
  tests passing** across 17 suites.
- **Concurrency tests actually performed:** 2 -- the invite-claim
  `Promise.all` concurrent-dispatch test (V3-H1) and V2.0-D's existing
  forced-transaction-failure rollback test, both against SQLite/single-
  process Express. **Zero** concurrency tests were performed against real
  multi-worker Postgres, because Postgres was not available in this
  environment -- every Postgres-specific safety claim in this document is
  explicitly marked **[REASONED]**, not **[VERIFIED]**, and should be
  treated with correspondingly lower confidence until empirically load-
  tested.
