-- Legacy Pulse PostgreSQL schema.
--
-- This is a REVIEWED port of backend/src/db/schema.sql (SQLite), not a
-- mechanical syntax substitution. Each table below notes what was
-- deliberately reconsidered, not just renamed, with particular attention
-- to constraints that enforce a security invariant.
--
-- TIMESTAMP DECISION (applies to every table): SQLite stores timestamps
-- as TEXT (ISO 8601 strings via strftime). Postgres gets a properly
-- typed TIMESTAMPTZ column here instead of TEXT -- a genuine improvement
-- (real temporal comparisons instead of lexicographic string
-- comparisons). To avoid silently changing what the application receives
-- when reading rows back (Node's `pg` driver returns JS Date objects for
-- timestamptz by default, not strings), the adapter
-- (db/postgres/adapter.js) configures a type parser that normalizes
-- every timestamptz value to the exact same ISO-8601 `...Z` string
-- format the SQLite path already produces.

DROP TABLE IF EXISTS schema_migrations CASCADE;
DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS release_confirmations CASCADE;
DROP TABLE IF EXISTS legacy_messages CASCADE;
DROP TABLE IF EXISTS photos CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS life_events CASCADE;
DROP TABLE IF EXISTS memories CASCADE;
DROP TABLE IF EXISTS trusted_contacts CASCADE;
DROP TABLE IF EXISTS beneficiaries CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- users: UNIQUE(email) is security-load-bearing, not incidental -- V2
-- finding C2's fix (trusted-contact claim email check) relies on "at
-- most one account can ever have this email" being a real database
-- guarantee. role/status CHECK constraints are defense-in-depth.
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'owner' CHECK (role IN ('owner', 'admin')),
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_secret_encrypted TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  token_version INTEGER NOT NULL DEFAULT 0,
  failed_login_count INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE profiles (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  date_of_birth TEXT,
  phone TEXT,
  bio TEXT,
  avatar_photo_id INTEGER
);

-- beneficiaries: invite_status CHECK constraint is directly relevant to
-- V3-H1 (the invite-claim atomic-UPDATE fix) -- ensures
-- 'pending'/'claimed'/'revoked' are the only reachable states at the DB
-- level, under genuine concurrent writers, which is the entire point of
-- this checkpoint.
CREATE TABLE beneficiaries (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  relationship TEXT,
  linked_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  invite_token_hash TEXT,
  invite_status TEXT NOT NULL DEFAULT 'pending' CHECK (invite_status IN ('pending', 'claimed', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_beneficiaries_owner ON beneficiaries(owner_id);
CREATE INDEX idx_beneficiaries_linked_user ON beneficiaries(linked_user_id);

CREATE TABLE trusted_contacts (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  linked_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  invite_token_hash TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_trusted_contacts_owner ON trusted_contacts(owner_id);
CREATE INDEX idx_trusted_contacts_linked_user ON trusted_contacts(linked_user_id);

CREATE TABLE memories (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('memory', 'story', 'instruction')),
  title TEXT NOT NULL,
  content_encrypted TEXT NOT NULL,
  tags TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_memories_owner ON memories(owner_id, type);

CREATE TABLE life_events (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description_encrypted TEXT,
  event_date TEXT NOT NULL,
  category TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_life_events_owner ON life_events(owner_id, event_date);

CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_filename_encrypted TEXT NOT NULL,
  stored_filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  description_encrypted TEXT,
  file_iv TEXT NOT NULL,
  file_auth_tag TEXT NOT NULL,
  enc_format TEXT NOT NULL DEFAULT 'v1',
  checksum_sha256 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_documents_owner ON documents(owner_id);

CREATE TABLE photos (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  memory_id INTEGER REFERENCES memories(id) ON DELETE SET NULL,
  life_event_id INTEGER REFERENCES life_events(id) ON DELETE SET NULL,
  caption_encrypted TEXT,
  stored_filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  file_iv TEXT NOT NULL,
  file_auth_tag TEXT NOT NULL,
  enc_format TEXT NOT NULL DEFAULT 'v1',
  checksum_sha256 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_photos_owner ON photos(owner_id);

-- legacy_messages: status/release_type CHECK constraints are the release
-- state machine's valid-state enumeration (V2.0-D).
CREATE TABLE legacy_messages (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  beneficiary_id INTEGER NOT NULL REFERENCES beneficiaries(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body_encrypted TEXT NOT NULL,
  release_type TEXT NOT NULL CHECK (release_type IN ('scheduled_date', 'trusted_contact_confirmation', 'immediate')),
  release_at TIMESTAMPTZ,
  required_confirmations INTEGER NOT NULL DEFAULT 2,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'released', 'revoked')),
  released_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_legacy_messages_owner ON legacy_messages(owner_id);
CREATE INDEX idx_legacy_messages_beneficiary ON legacy_messages(beneficiary_id);
CREATE INDEX idx_legacy_messages_release_scan ON legacy_messages(status, release_type, release_at);

-- release_confirmations: UNIQUE(owner_id, trusted_contact_id) is THE
-- constraint V3-M1's fix depends on -- turns a duplicate confirmation
-- race into a clean, catchable 23505 (unique_violation) instead of
-- silently double-counting.
CREATE TABLE release_confirmations (
  id SERIAL PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  trusted_contact_id INTEGER NOT NULL REFERENCES trusted_contacts(id) ON DELETE CASCADE,
  confirmed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(owner_id, trusted_contact_id)
);

CREATE TABLE refresh_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id INTEGER,
  ip_address TEXT,
  metadata_json TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE TABLE notifications (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  message TEXT NOT NULL,
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notifications_user ON notifications(user_id, read_at);

CREATE TABLE schema_migrations (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
