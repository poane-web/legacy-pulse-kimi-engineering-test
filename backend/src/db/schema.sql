-- Legacy Pulse database schema (SQLite)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'admin')),
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret_encrypted TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  password_changed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS profiles (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, date_of_birth TEXT, phone TEXT, bio TEXT, avatar_photo_id INTEGER);
CREATE TABLE IF NOT EXISTS beneficiaries (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, full_name TEXT NOT NULL, email TEXT NOT NULL, relationship TEXT, linked_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, invite_token_hash TEXT, invite_status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_beneficiaries_owner ON beneficiaries(owner_id); CREATE INDEX IF NOT EXISTS idx_beneficiaries_linked_user ON beneficiaries(linked_user_id);
CREATE TABLE IF NOT EXISTS trusted_contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, full_name TEXT NOT NULL, email TEXT NOT NULL, linked_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, invite_token_hash TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_trusted_contacts_owner ON trusted_contacts(owner_id); CREATE INDEX IF NOT EXISTS idx_trusted_contacts_linked_user ON trusted_contacts(linked_user_id);
CREATE TABLE IF NOT EXISTS memories (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL CHECK (type IN ('memory','story','instruction')), title TEXT NOT NULL, content_encrypted TEXT NOT NULL, tags TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_memories_owner ON memories(owner_id,type);
CREATE TABLE IF NOT EXISTS life_events (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, description_encrypted TEXT, event_date TEXT NOT NULL, category TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_life_events_owner ON life_events(owner_id,event_date);
CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, original_filename_encrypted TEXT NOT NULL, stored_filename TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, description_encrypted TEXT, file_iv TEXT NOT NULL, file_auth_tag TEXT NOT NULL, checksum_sha256 TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, memory_id INTEGER REFERENCES memories(id) ON DELETE SET NULL, life_event_id INTEGER REFERENCES life_events(id) ON DELETE SET NULL, caption_encrypted TEXT, stored_filename TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, file_iv TEXT NOT NULL, file_auth_tag TEXT NOT NULL, checksum_sha256 TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_photos_owner ON photos(owner_id);
CREATE TABLE IF NOT EXISTS legacy_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, beneficiary_id INTEGER NOT NULL REFERENCES beneficiaries(id) ON DELETE CASCADE, title TEXT NOT NULL, body_encrypted TEXT NOT NULL, release_type TEXT NOT NULL CHECK (release_type IN ('scheduled_date','trusted_contact_confirmation','immediate')), release_at TEXT, required_confirmations INTEGER NOT NULL DEFAULT 2, status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','released','revoked')), released_at TEXT, config_version INTEGER NOT NULL DEFAULT 1, released_recipient_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_legacy_messages_owner ON legacy_messages(owner_id); CREATE INDEX IF NOT EXISTS idx_legacy_messages_beneficiary ON legacy_messages(beneficiary_id); CREATE INDEX IF NOT EXISTS idx_legacy_messages_release_scan ON legacy_messages(status,release_type,release_at); CREATE INDEX IF NOT EXISTS idx_legacy_messages_config_version ON legacy_messages(id,config_version); CREATE INDEX IF NOT EXISTS idx_legacy_messages_released_recipient ON legacy_messages(released_recipient_user_id);
CREATE TABLE IF NOT EXISTS release_confirmations (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, trusted_contact_id INTEGER NOT NULL REFERENCES trusted_contacts(id) ON DELETE CASCADE, confirmed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_release_confirmations_owner ON release_confirmations(owner_id);
CREATE TABLE IF NOT EXISTS refresh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id); CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL, target_type TEXT, target_id INTEGER, ip_address TEXT, metadata_json TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_user_id); CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL, message TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,read_at);
CREATE TABLE IF NOT EXISTS schema_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));