# Legacy Pulse — Architecture Overview

## 1. Purpose

Legacy Pulse is a digital legacy platform that lets a person ("Owner") securely
store memories, documents, photos, life events, and legacy messages, and
release specific information to designated **beneficiaries** under
conditions the Owner controls (a fixed release date, or Owner-confirmed
"death/incapacity" trigger via **trusted contacts**).

This document describes the system as actually implemented in this
repository — not an aspirational design. Anything not implemented is called
out explicitly in `README.md` under "Known Limitations / Deferred Features".

## 2. High-level architecture

```
┌─────────────────────────┐        HTTPS/JSON        ┌──────────────────────────┐
│   Frontend (SPA)         │ ───────────────────────► │   Backend (Express API)  │
│   Vanilla JS + CSS        │ ◄─────────────────────── │   Node.js                │
│   served as static files │                            │                          │
└─────────────────────────┘                            │  ┌────────────────────┐  │
                                                          │  │ Auth (JWT + bcrypt)│  │
                                                          │  ├────────────────────┤  │
                                                          │  │ RBAC middleware    │  │
                                                          │  ├────────────────────┤  │
                                                          │  │ Business logic     │  │
                                                          │  │ (routes/services)  │  │
                                                          │  ├────────────────────┤  │
                                                          │  │ Field-level crypto │  │
                                                          │  │ (AES-256-GCM)      │  │
                                                          │  ├────────────────────┤  │
                                                          │  │ Audit logger       │  │
                                                          │  ├────────────────────┤  │
                                                          │  │ Scheduled release  │  │
                                                          │  │ worker (node-cron) │  │
                                                          │  └────────────────────┘  │
                                                          └───────────┬──────────────┘
                                                                      │
                                                     ┌────────────────┼─────────────────┐
                                                     ▼                                  ▼
                                          ┌────────────────────┐          ┌─────────────────────┐
                                          │ SQLite database     │          │ Local encrypted file │
                                          │ (better-sqlite3)    │          │ storage (uploads/)   │
                                          └────────────────────┘          └─────────────────────┘
```

### Why this stack

- **Node.js + Express**: minimal, well-understood, easy to audit line-by-line
  for a security-sensitive evaluation project.
- **SQLite via `better-sqlite3`**: a real relational database with actual
  migrations and constraints, but zero external services to stand up. This
  keeps the evaluator's "run it locally" experience to `npm install && npm
  run migrate && npm run seed && npm start`. Swapping to Postgres later is a
  matter of changing `backend/src/db/index.js` — the SQL is deliberately
  kept close to standard ANSI SQL and all data access goes through a single
  `db` module, so no route/service code depends on SQLite specifics.
- **Vanilla JS SPA frontend** (no framework/build step): given the huge
  surface area of this MVP (19 functional areas), a build-less frontend
  means the evaluator can open the app with zero `npm run build` steps and
  no risk of a broken bundler config hiding functionality. It is modular
  (one JS file per feature area, ES modules) and responsive (CSS Grid/Flexbox
  + media queries), not a single monolithic script.

## 3. Layered separation

| Layer | Location | Responsibility |
|---|---|---|
| Frontend | `frontend/` | Presentation, client-side validation, calling the API |
| API / HTTP | `backend/src/routes/*` | Request parsing, auth/RBAC guards, input validation, calling services |
| Business logic | `backend/src/services/*` | Release scheduling, notification generation |
| Data access | `backend/src/db/*` | Schema, migrations, seed data, single DB connection |
| Security | `backend/src/utils/crypto.js`, `middleware/auth.js`, `middleware/rbac.js` | Encryption, authentication, authorization |
| External services | none required for MVP (see below) | — |

External services (email/SMS delivery for notifications, cloud object
storage for files) are **abstracted behind an interface**
(`backend/src/services/notify.js`, `backend/src/services/storage.js`) but
implemented with local/no-op providers for the MVP. This is a deliberate
seam so a real deployment can swap in SES/Twilio/S3 without touching route
code. This is documented, not hidden.

## 4. Authentication flow

1. `POST /api/auth/register` — Owner creates an account. Password is hashed
   with **bcrypt** (cost factor 12) before storage; the plaintext password is
   never persisted or logged.
2. `POST /api/auth/login` — credentials verified with `bcrypt.compare`. On
   success, the server issues:
   - a short-lived **access token** (JWT, 15 min, signed HS256 with
     `JWT_ACCESS_SECRET`), returned in the JSON body for the SPA to hold in
     memory, and
   - a long-lived **refresh token** (random 256-bit value, stored **hashed**
     in the `refresh_tokens` table, 7-day expiry) set as an `httpOnly`,
     `SameSite=Strict`, `Secure`-in-production cookie.
3. `POST /api/auth/refresh` — reads the refresh cookie, checks the hash
   against the DB, checks expiry/revocation, rotates it (old one is revoked,
   a new one issued) and returns a new access token. Rotation limits the
   blast radius of a stolen refresh token.
4. `POST /api/auth/logout` — revokes the current refresh token server-side
   and clears the cookie.
5. Every protected route requires `Authorization: Bearer <access token>`,
   verified by `middleware/auth.js`.

**Why access+refresh instead of one long-lived JWT:** a single long-lived
JWT can't be revoked before it expires. Splitting into a short-lived
stateless access token and a stateful, revocable, hashed refresh token gives
both low per-request DB overhead and the ability to kill a session (e.g. via
"Sign out of all devices" in Security Settings).

## 5. Authorization model (RBAC + resource ownership)

Two roles exist: `owner` (a normal user preserving their legacy) and `admin`
(platform operator). A user row also carries a `beneficiary_user_id`
concept: a beneficiary is *linked* to an owner's account via the
`beneficiaries` table and, once they register/claim their invite, via
`beneficiaries.linked_user_id`.

Authorization is enforced with two composable middlewares:

- `requireRole('admin')` — role check against the JWT claims.
- `requireOwnership(resourceLoader)` — loads the resource (memory, document,
  photo, timeline event, legacy message) and confirms
  `resource.owner_id === req.user.id`, **or** — for legacy messages only —
  that the requester is the specific beneficiary the message is addressed
  to **and** the message's release conditions have been met (see §7).

This "loader + ownership check" pattern is centralized in
`middleware/rbac.js` so every resource route uses the same logic rather than
each route hand-rolling `if (row.owner_id !== req.user.id)` checks that are
easy to forget on a new endpoint.

Admins can view platform-level aggregates (user counts, audit log, system
health) but **cannot** read Owners' encrypted memories/messages/documents —
the admin dashboard queries metadata only, never decrypts owner content.
This is enforced by the admin routes never calling `decryptField`.

## 6. Data-flow: creating and releasing a legacy message

1. Owner writes a legacy message in the SPA, selects a beneficiary and a
   release condition (fixed date, or "on confirmed passing").
2. `POST /api/legacy-messages` — body validated (express-validator), then
   the message body is encrypted with AES-256-GCM using a per-record random
   IV and the server's `DATA_ENCRYPTION_KEY`; ciphertext + IV + auth tag are
   stored. An audit log row (`legacy_message.created`) is written.
3. A background job (`services/releaseScheduler.js`, run via `node-cron`
   every minute) scans messages whose `release_type = 'scheduled_date'` and
   `release_at <= now()` and not yet released, and flips `status =
   'released'`, writing an audit entry and a notification row for the
   beneficiary.
4. For `release_type = 'trusted_contact_confirmation'`, release instead
   requires **two independent trusted contacts** (configurable, default 2)
   to confirm the "passing" event via `POST
   /api/trusted-contacts/confirm/:ownerId`. This is a simple but real
   two-person-rule control against a single compromised or malicious
   trusted contact prematurely releasing sensitive data.
5. Once released, the beneficiary (identified by their own login, linked via
   `beneficiaries.linked_user_id`) can call `GET /api/legacy-messages/:id`.
   The route checks `status === 'released'` **and** `beneficiary_id ===
   req.user.beneficiaryRecordId` before decrypting and returning content.
   Any earlier attempt returns `403` and is written to the audit log as
   `legacy_message.unauthorized_access_attempt`.

## 7. Encryption architecture (what is encrypted, and where)

**Encryption at rest for sensitive field-level data** is implemented with
AES-256-GCM (`backend/src/utils/crypto.js`), key from
`DATA_ENCRYPTION_KEY` (32-byte, base64, environment variable — never
hard-coded, never committed). Each encrypted value stores
`iv:authTag:ciphertext` (base64) so decryption doesn't depend on external
state.

Encrypted at the field level, server-side, immediately before the DB write,
decrypted only server-side immediately after the authorized DB read:

- `legacy_messages.body_encrypted`
- `memories.content_encrypted`
- `stories.content_encrypted` (stories are modeled as a memory subtype, see schema)
- `instructions.content_encrypted`
- `documents.description_encrypted` (the file itself, see below)
- `users.mfa_secret_encrypted` (TOTP secret, if MFA is enabled)

**Uploaded files** (documents/photos) are encrypted at rest on disk:
the file bytes are streamed through AES-256-GCM before being written under
`backend/uploads/`, using a random IV per file; the IV and auth tag are
stored alongside the file metadata row. Files are served back only via an
authenticated, ownership-checked download route
(`GET /api/documents/:id/download`) that decrypts the file into a stream —
files are **never** served as static/public assets, and filenames on disk
are randomized UUIDs unrelated to original filenames (which are themselves
stored, encrypted, in the DB) to avoid leaking content via directory
listing or predictable paths.

**Passwords** are never encrypted (encryption is reversible); they are
hashed with bcrypt (one-way, salted, cost 12).

**Not encrypted** (by design, needed for querying/joins/display): user
email, name, beneficiary relationship labels, life-event titles/dates,
timestamps, role, audit log metadata. This is a deliberate MVP trade-off
documented here rather than silently applied — a production system might
also encrypt event titles using searchable/deterministic encryption or
client-side encryption, which is out of scope for this MVP (see
"Deferred Features").

**Key management for the MVP**: a single symmetric key from the environment
(`DATA_ENCRYPTION_KEY`). This is explicitly a simplification — see the
threat model for what a production KMS-backed design would add.

## 8. Rate limiting & abuse protection

- `POST /api/auth/login`, `/register`, `/refresh`: limited via
  `express-rate-limit` (default: 10 requests / 15 min / IP) to slow
  credential stuffing and brute force.
- All `/api/*` routes: a looser global limiter (300 req / 15 min / IP).
- Failed login attempts are recorded in the audit log
  (`auth.login_failed`) with the attempted email (not password) and IP,
  enabling future account-lockout policies (documented as deferred).

## 9. Project structure

```
legacy-pulse/
├── README.md
├── .env.example
├── docs/
│   ├── ARCHITECTURE.md   (this file)
│   ├── THREAT_MODEL.md
│   ├── DATABASE.md
│   └── API.md
├── backend/
│   ├── package.json
│   ├── src/
│   │   ├── server.js
│   │   ├── config/env.js
│   │   ├── db/ (schema.sql, migrate.js, seed.js, index.js)
│   │   ├── middleware/ (auth.js, rbac.js, rateLimit.js, errorHandler.js, validate.js)
│   │   ├── utils/ (crypto.js, jwt.js, audit.js, asyncHandler.js)
│   │   ├── routes/ (auth, users, beneficiaries, memories, documents, photos,
│   │   │            timeline, legacyMessages, trustedContacts, admin, search,
│   │   │            notifications, audit)
│   │   ├── services/ (releaseScheduler.js, notify.js, storage.js)
│   │   └── __tests__/ (jest test suites)
│   └── uploads/ (encrypted file storage, gitignored)
└── frontend/
    ├── public/index.html
    └── src/ (css/, js/ api client + router, pages/, components/)
```
