# Legacy Pulse — Database Schema & Entity Relationships

Engine: SQLite (file-based, `backend/data/legacy_pulse.db`), managed through
`better-sqlite3`. Schema lives in `backend/src/db/schema.sql` and is applied
by `backend/src/db/migrate.js`. Migrations are numbered files under
`backend/src/db/migrations/` applied in order and tracked in a
`schema_migrations` table, so re-running `npm run migrate` is idempotent.

## Entity relationship summary

```
users (1) ──< beneficiaries >── (0..1) users              [beneficiary optionally claims an account]
users (1) ──< trusted_contacts >── (0..1) users
users (1) ──< memories
users (1) ──< documents
users (1) ──< photos
users (1) ──< life_events
users (1) ──< legacy_messages >── (1) beneficiaries
users (1) ──< refresh_tokens
users (1) ──< audit_logs
users (1) ──< notifications
legacy_messages (1) ──< release_confirmations >── (1) trusted_contacts
memories (0..1) ──< photos                (a photo can be attached to a memory)
life_events (0..1) ──< photos             (a photo can be attached to a life event)
```

## Tables

### users
Core account table for both owners and admins, and for beneficiaries once
they register to claim access.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| email | TEXT UNIQUE NOT NULL | lowercase-normalized |
| password_hash | TEXT NOT NULL | bcrypt |
| full_name | TEXT NOT NULL | |
| role | TEXT NOT NULL DEFAULT 'owner' | `owner` \| `admin` |
| mfa_enabled | INTEGER DEFAULT 0 | boolean |
| mfa_secret_encrypted | TEXT | AES-256-GCM, null unless MFA enabled |
| status | TEXT DEFAULT 'active' | `active` \| `disabled` |
| created_at, updated_at | TEXT (ISO8601) | |

### profiles
1:1 extension of `users` for non-auth personal profile data.

| column | type | notes |
|---|---|---|
| user_id | INTEGER PK, FK users.id | |
| date_of_birth | TEXT | |
| phone | TEXT | |
| bio | TEXT | not encrypted (user-controlled public-ish bio) |
| avatar_photo_id | INTEGER FK photos.id NULL | |

### beneficiaries
A relationship record created by an Owner. Not itself a login — becomes
linkable to a `users` row when the invited person registers with the
matching invite token/email.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | the Owner who created this beneficiary |
| full_name | TEXT NOT NULL | |
| email | TEXT NOT NULL | |
| relationship | TEXT | e.g. "Daughter", "Spouse" |
| linked_user_id | INTEGER FK users.id NULL | set once beneficiary claims account |
| invite_token_hash | TEXT | sha256 of invite token, null after claimed |
| invite_status | TEXT DEFAULT 'pending' | `pending` \| `claimed` \| `revoked` |
| created_at | TEXT | |

### trusted_contacts
People an Owner designates to confirm a "release" trigger event (e.g.
confirming the Owner has passed away), independent of beneficiaries.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | |
| full_name, email | TEXT | |
| linked_user_id | INTEGER FK users.id NULL | |
| invite_token_hash | TEXT | |
| status | TEXT DEFAULT 'pending' | `pending` \| `active` \| `revoked` |
| created_at | TEXT | |

### memories
Free-form memories/personal stories. `type` distinguishes "memory" vs
"story" vs "instruction" as they share the same shape (title + long-form
encrypted content) rather than three near-duplicate tables.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | |
| type | TEXT NOT NULL | `memory` \| `story` \| `instruction` |
| title | TEXT NOT NULL | |
| content_encrypted | TEXT NOT NULL | AES-256-GCM ciphertext |
| tags | TEXT | comma-separated, for search |
| created_at, updated_at | TEXT | |

### documents
Uploaded file metadata; bytes live encrypted on disk under `backend/uploads`.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | |
| original_filename_encrypted | TEXT NOT NULL | |
| stored_filename | TEXT NOT NULL | random UUID on disk |
| mime_type | TEXT | validated allow-list |
| size_bytes | INTEGER | |
| description_encrypted | TEXT | |
| file_iv | TEXT NOT NULL | base64 IV used for file encryption |
| file_auth_tag | TEXT NOT NULL | base64 GCM auth tag |
| checksum_sha256 | TEXT | of plaintext, for integrity verification on download |
| created_at | TEXT | |

### photos
Same shape as documents but semantically photos; kept as a separate table
because photos can attach to a memory or a life event and are displayed
differently (galleries/thumbnails) than generic documents.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | |
| memory_id | INTEGER FK memories.id NULL | |
| life_event_id | INTEGER FK life_events.id NULL | |
| caption_encrypted | TEXT | |
| stored_filename | TEXT NOT NULL | |
| mime_type, size_bytes | | validated image types only |
| file_iv, file_auth_tag | TEXT NOT NULL | |
| checksum_sha256 | TEXT | |
| created_at | TEXT | |

### life_events
Timeline entries.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | |
| title | TEXT NOT NULL | |
| description_encrypted | TEXT | |
| event_date | TEXT NOT NULL | ISO date, user-supplied, may be approximate |
| category | TEXT | e.g. "Career", "Family", "Milestone" |
| created_at | TEXT | |

### legacy_messages
Messages addressed to a specific beneficiary, released under a condition.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | |
| beneficiary_id | INTEGER FK beneficiaries.id NOT NULL | |
| title | TEXT NOT NULL | |
| body_encrypted | TEXT NOT NULL | |
| release_type | TEXT NOT NULL | `scheduled_date` \| `trusted_contact_confirmation` \| `immediate` |
| release_at | TEXT NULL | required if release_type = scheduled_date |
| required_confirmations | INTEGER DEFAULT 2 | used if release_type = trusted_contact_confirmation |
| status | TEXT NOT NULL DEFAULT 'pending' | `pending` \| `released` \| `revoked` |
| released_at | TEXT NULL | |
| created_at | TEXT | |

### release_confirmations
Records each trusted contact's confirmation toward the "two-person rule".

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| owner_id | INTEGER FK users.id NOT NULL | the owner being confirmed as deceased/incapacitated |
| trusted_contact_id | INTEGER FK trusted_contacts.id NOT NULL | |
| confirmed_at | TEXT NOT NULL | |
| UNIQUE(owner_id, trusted_contact_id) | | one confirmation per contact per owner |

### refresh_tokens
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| user_id | INTEGER FK users.id NOT NULL | |
| token_hash | TEXT NOT NULL | sha256 of the raw token; raw token never stored |
| expires_at | TEXT NOT NULL | |
| revoked_at | TEXT NULL | |
| created_at | TEXT | |

### audit_logs
Append-only. No update/delete route exists for this table.

| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| actor_user_id | INTEGER FK users.id NULL | null for unauthenticated events (e.g. failed login) |
| action | TEXT NOT NULL | e.g. `auth.login_success`, `legacy_message.created` |
| target_type | TEXT | e.g. `legacy_message` |
| target_id | INTEGER | |
| ip_address | TEXT | |
| metadata_json | TEXT | small non-sensitive context, never raw content |
| created_at | TEXT | |

### notifications
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| user_id | INTEGER FK users.id NOT NULL | recipient |
| type | TEXT NOT NULL | e.g. `message_released`, `beneficiary_invited` |
| message | TEXT NOT NULL | plain text, non-sensitive summary only |
| read_at | TEXT NULL | |
| created_at | TEXT | |

## Indexing

Indexes are created on all foreign keys used in lookups (`owner_id` on every
owned table, `beneficiary_id`, `user_id`), plus `users.email` (unique),
`legacy_messages.status` + `release_at` (for the scheduler's scan query),
and a composite index for search over `memories(owner_id, tags)`.

## Referential integrity

`PRAGMA foreign_keys = ON` is set on every connection. All child tables use
`ON DELETE CASCADE` from `users`, so deleting an account (Security Settings
→ "Delete my account") removes owned content — implemented and tested. Note
this is a hard delete for the MVP; a production system would likely do a
soft-delete/retention-hold instead (documented as a deferred enhancement).
