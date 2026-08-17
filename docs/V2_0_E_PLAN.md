# Legacy Pulse V2 — Checkpoint V2.0-E: Life-Event Architecture

Scope, per `docs/V2_SECURITY_AUDIT.md` §"Areas out of scope for V2 Phase
1": "Life-event/photo/memory data-model coupling and richer authorization
nuance." Unlike H2/H3/M1, this wasn't a specific numbered finding — it was
flagged as an area needing a closer pass once the higher-severity items
were handled. This checkpoint is that pass.

## What was found on inspection

1. **A photo can be linked to both a memory AND a life event
   simultaneously**, or neither — the schema (`memory_id`, `life_event_id`,
   both nullable FKs) and the API (`POST /photos` accepts both fields
   independently) never rule this out. Nothing was exploitable here (both
   FKs are independently ownership-checked — see below), but it's a data
   model ambiguity: what does it mean for a photo to illustrate both a
   specific memory and a specific life event at once? The product concept
   doesn't have an answer, so the model shouldn't allow it silently.

2. **Cross-owner attachment was already correctly guarded**
   (`photos.routes.js` checks `memory.owner_id === req.user.id` and
   `life_event.owner_id === req.user.id` before allowing an attach) — but
   had **no regression test** proving it. Re-validated by reading the code
   (this is real, not a gap), then closed the test-coverage gap.

3. **No way to fetch photos scoped to a specific memory or life event.**
   The only read path was the flat `GET /photos` list (all of an owner's
   photos, with `memoryId`/`lifeEventId` in the DTO for the client to
   filter itself). For a "timeline" feature, not having
   `GET /timeline/:id/photos` / `GET /memories/:id/photos` is a real API
   completeness gap, not just a nice-to-have — every other resource
   relationship in this app has a scoped read path except this one.

4. **No way to re-attach/detach a photo after upload.** Once uploaded with
   a `memoryId`, a photo could never be moved to a different memory,
   attached to a life event instead, or detached — the only options were
   "delete and re-upload" (wasteful — the bytes are identical, only the
   metadata should change) or live with the original attachment forever.

## Changes implemented

### 1. Mutual exclusivity enforced at the application layer
`POST /photos` and the new `PUT /photos/:id/attachment` (see below) now
reject a request that sets both `memoryId` and `lifeEventId`.

**Why application-layer, not a DB `CHECK` constraint:** SQLite does not
support adding a `CHECK` constraint to an existing table via `ALTER
TABLE` — only at `CREATE TABLE` time. Retrofitting one onto `photos`
would require the full recreate-copy-drop-rename sequence SQLite
recommends for schema changes it doesn't support incrementally, which is
a real migration risk (a bug in that sequence corrupts the whole table)
for a constraint the application can enforce with equal correctness and
zero migration risk. This is a deliberate, documented choice, consistent
with the additive-only migration philosophy established in
`docs/V2_0_C_PLAN.md`.

### 2. Scoped read filtering
`GET /photos?memoryId=X` / `GET /photos?lifeEventId=Y` — filters the
existing photo list to a specific memory or life event, with the same
ownership check applied to the filter target itself (a caller can't probe
whether *another user's* memory/life-event ID exists by filtering on it).
Implemented as query parameters on the existing endpoint rather than new
nested routes (`GET /timeline/:id/photos`), since photos remain the one
canonical resource and this avoids importing one router's DTO logic into
another.

### 3. Re-attachment endpoint
`PUT /photos/:id/attachment` — lets an owner move a photo between "no
context," "attached to memory X," or "attached to life event Y," with the
same ownership and mutual-exclusivity checks as creation. Ownership of
the *photo itself* is enforced via the existing `requireOwnership`
pattern.

## What this checkpoint deliberately does not do

While auditing this area, a larger product gap became visible: **legacy
messages can only ever contain text — there is no mechanism for a
beneficiary to ever receive an owner's memories, photos, documents, or
life-event timeline**, even after a release condition is met. Everything
except `legacy_messages` is permanently owner-only. For a product whose
stated purpose includes preserving "photos," "important documents," and a
"life-event timeline" *for* beneficiaries, this is arguably the more
important architectural question — but it's a genuinely new feature (a
beneficiary-facing release/sharing model for non-message content), not an
architecture *hardening* pass on the existing life-event/photo/memory
relationships this checkpoint's name describes. Building it properly
deserves its own scoped design pass rather than being bolted on here
under a "life-event architecture" checkpoint that was really about the
data-model coupling issues above. **Flagged explicitly as a V3
recommendation** (see the final V2 report) rather than silently left
unaddressed.

## Database changes

**None.** All changes in this checkpoint are route/validation logic —
consistent with choosing application-layer enforcement over a schema
change for the mutual-exclusivity rule.
