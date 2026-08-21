# Legacy Pulse — Temporal Business Logic Security

## Threat model

Legacy Pulse makes security decisions using time and changing relationships. A valid authorization at time T must not automatically remain valid after the protected object, beneficiary, trusted contact, or release state changes.

## V2 temporal invariants

1. **Canonical time:** scheduled release timestamps are normalized to UTC before persistence. Release comparisons therefore do not depend on the textual representation of an offset.
2. **Release is a state transition:** a scheduled message can move from `pending` to `released` only through an atomic update whose predicate still requires the row to be pending and due.
3. **No stale edits:** owner edits and deletes re-check `status = pending` inside the write. A stale authorization read cannot modify or delete a message after another worker has released it.
4. **Release confirmations are message-scoped:** a trusted contact's confirmation authorizes exactly one `legacy_message_id`. Confirmations for another message, or legacy owner-wide confirmation rows, do not satisfy the target message's release policy.
5. **Required confirmations are message data:** release uses the target message's `required_confirmations`, not a mutable global count.
6. **Beneficiary records are retention-sensitive:** a beneficiary referenced by any legacy message cannot be deleted, because the existing foreign-key cascade would otherwise destroy historical or pending legacy content.
7. **Post-release identity is stable:** the beneficiary relationship cannot be silently deleted underneath a released message through the API.

## Known remaining temporal risks

- The MVP does not yet model milestone/event-triggered releases as first-class immutable policies.
- There is no dedicated event-version or policy-version field on legacy messages yet; future product work should add one before allowing beneficiaries, policies, or release conditions to change after scheduling.
- SQLite is suitable for the MVP but concurrency behavior must be load-tested again on the production database engine.
- Notification delivery is outside the release transaction; the durable-outbox pattern should be used before production deployment.
