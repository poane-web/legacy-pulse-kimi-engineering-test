-- Bind a scheduled release to one coherent configuration and recipient.
ALTER TABLE legacy_messages ADD COLUMN config_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE legacy_messages ADD COLUMN released_recipient_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
UPDATE legacy_messages
SET released_recipient_user_id = (
  SELECT b.linked_user_id FROM beneficiaries b WHERE b.id = legacy_messages.beneficiary_id
)
WHERE status = 'released' AND released_recipient_user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_legacy_messages_config_version ON legacy_messages(id, config_version);
CREATE INDEX IF NOT EXISTS idx_legacy_messages_released_recipient ON legacy_messages(released_recipient_user_id);
