-- V2 temporal hardening: confirmations must authorize one specific message.
-- Existing owner-wide confirmations are retained for audit/history but are
-- intentionally not eligible for any new message release.
ALTER TABLE release_confirmations ADD COLUMN legacy_message_id INTEGER REFERENCES legacy_messages(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS ux_release_confirmations_message_contact
  ON release_confirmations(legacy_message_id, trusted_contact_id)
  WHERE legacy_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_release_confirmations_message
  ON release_confirmations(legacy_message_id);
