# Legacy Pulse V2 — Checkpoint V2.0-E: Life-Event Architecture

Full design rationale in `docs/V2_0_E_PLAN.md`. This document is the
"what was done and how it was verified" report.

## Changes implemented

1. **Mutual exclusivity**: a photo can no longer be attached to both a
   memory and a life event simultaneously (`POST /photos` and the new
   `PUT /photos/:id/attachment`). Enforced at the application layer —
   documented reasoning for not retrofitting a DB `CHECK` constraint in
   `docs/V2_0_E_PLAN.md`.
2. **Scoped filtering**: `GET /photos?memoryId=` / `?lifeEventId=` — the
   filter target's ownership is checked (a caller can't probe whether
   another user's memory/life-event ID exists by filtering on it).
3. **Re-attachment**: `PUT /photos/:id/attachment` — move a photo between
   memory/life-event/detached without deleting and re-uploading identical
   bytes. Ownership of the photo itself enforced via the existing
   `requireOwnership` pattern; ownership of the new attachment target
   checked the same way as at creation time.
4. **Re-verified (not newly added) IDOR protection**: cross-owner
   attachment on create was already correctly guarded in the codebase —
   closed the test-coverage gap rather than fixing a bug, since reading
   the code confirmed there wasn't one here.

## What this checkpoint identified but deliberately did not build

Auditing this area surfaced a larger product-level gap: **only
`legacy_messages` can ever be released to a beneficiary** — memories,
photos, documents, and the life-event timeline are permanently
owner-only, with no release/sharing mechanism at all, even after a
release condition is met. For a "digital legacy platform," this is
arguably a more significant architectural question than the data-model
coupling issues this checkpoint fixed, but it's a genuinely new feature
(a beneficiary-facing content-release model), not a hardening pass on
existing relationships. Flagged explicitly as a **V3 recommendation**
rather than attempted as a rushed addition here — see the final V2
summary report.

## New tests

10 new tests in `v2e_lifeEventArchitecture.test.js`: mutual-exclusivity
rejection (create and re-attach), the "no regression" case (single
attachment still works), cross-owner IDOR checks for both memory and
life-event attachment targets (create and via the scoped filter query),
re-attachment ownership check on the photo itself, and full detachment.

**Full suite: 100/100 passing** (90 from V2.0-D + 10 new).

## Database changes

**None** — deliberately application-layer only, per the reasoning in
`docs/V2_0_E_PLAN.md` §1.

## Exact commands to reproduce

```bash
cd backend
npm install
cp ../.env.example .env
npm run migrate
npm test   # expect 100/100 passing, including v2e_lifeEventArchitecture.test.js
```
