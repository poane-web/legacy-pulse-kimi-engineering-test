-- V3 temporal hardening: once a trusted-contact quorum begins, bind the
-- release to the beneficiary identity that was current at the first
-- authorization step. Later relationship mutations must never silently
-- redirect the already-authorized release to a different user.
ALTER TABLE legacy_messages ADD COLUMN release_recipient_snapshot_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_legacy_messages_recipient_snapshot
  ON legacy_messages(release_recipient_snapshot_user_id);
