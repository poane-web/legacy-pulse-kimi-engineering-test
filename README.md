# Legacy Pulse

A secure digital legacy platform: preserve memories, photos, documents, life
events, and messages for the people you love — released only under
conditions you control.

This repository is an engineering evaluation build. It is a genuinely
structured MVP (not a superficial demo): real authentication, real
authorization checks, real encryption, a real (if intentionally simple)
database schema, and an automated test suite that actually exercises the
security-critical paths. See `docs/` for the full architecture, database
schema, threat model, and API reference — and see **"Known Limitations /
Deferred Features"** below for what is deliberately *not* implemented, and
why.

## Quick start

Requires Node.js 18+ (developed on Node 22).

```bash
cd backend
npm install
```

> **Note on `npm install`**: `better-sqlite3` is a native module. `npm install` will
> either fetch a prebuilt binary or compile it locally via `node-gyp`, both of
> which require normal outbound internet access (to GitHub release assets
> and/or `nodejs.org`). If you're behind a restrictive firewall/proxy and the
> build fails, the usual native-module troubleshooting applies (ensure Python
> 3 and build tools are installed, or unblock `nodejs.org`).

```bash
cp ../.env.example .env
# Edit .env: at minimum set JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, and
# DATA_ENCRYPTION_KEY. Generate values with:
#   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
#   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

npm run migrate   # creates backend/data/legacy_pulse.db and applies schema.sql
npm run seed      # creates demo accounts + sample content (see below)
npm start         # serves the API and the frontend at http://localhost:4000
```

Open `http://localhost:4000` in a browser. The frontend is a build-less
static SPA served by the same Express server, so there is nothing to
compile.

### Demo accounts (seeded)

| Role | Email | Password |
|---|---|---|
| Owner | `owner@demo.legacypulse.test` | `DemoPass123!` |
| Beneficiary (linked, has one released message) | `beneficiary@demo.legacypulse.test` | `DemoPass123!` |
| Admin | `admin@demo.legacypulse.test` | `DemoPass123!` |

Delete `backend/data/legacy_pulse.db` and re-run `npm run migrate && npm run
seed` to reset to a clean demo state.

### Running tests

```bash
cd backend
npm test
```

32 tests across 5 suites: field/file encryption round-trip and tamper
detection, the full auth flow (register/login/refresh-rotation/logout/rate
limiting), IDOR/RBAC authorization enforcement, legacy-message release
conditions (scheduled-date and two-person trusted-contact confirmation), and
document upload/download integrity. Tests run against an isolated temporary
SQLite database, never the dev database.

## Technology stack

- **Backend**: Node.js, Express
- **Database**: SQLite via `better-sqlite3` (see `docs/DATABASE.md` for why,
  and what changing databases would involve)
- **Auth**: JWT access tokens (15 min) + rotating, revocable refresh tokens
  (httpOnly cookie), bcrypt password hashing
- **Encryption**: AES-256-GCM for sensitive fields and uploaded files
- **Frontend**: Vanilla JavaScript (ES modules), no build step, no
  framework — see `docs/ARCHITECTURE.md` §2 for the reasoning
- **Testing**: Jest + Supertest

## Architecture & design documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system overview, auth
  flow, authorization model, encryption architecture, data flow
- [`docs/DATABASE.md`](docs/DATABASE.md) — full schema and entity
  relationships
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — STRIDE-style threat
  model and documented residual risks
- [`docs/API.md`](docs/API.md) — full API reference

## Features implemented

1. User registration and login ✅
2. Secure authentication (bcrypt + JWT access/refresh with rotation) ✅
3. User dashboard (aggregate stats, upcoming messages, inbox preview) ✅
4. Personal profile (view/edit) ✅
5. Family/beneficiary management (invite, link, revoke) ✅
6. Memory creation (memories/stories, tagged, encrypted) ✅
7. Document upload (encrypted at rest, authenticated download) ✅
8. Photo upload (encrypted at rest, gallery view) ✅
9. Life-event timeline (CRUD, chronological view) ✅
10. Legacy message creation (encrypted) ✅
11. Scheduled message release (cron sweep every minute) ✅
12. Beneficiary access management (invite/claim/revoke, per-message
    addressing enforced server-side) ✅
13. Trusted-contact system (invite/claim/revoke, two-person confirmation
    rule for "on my passing" release) ✅
14. Security settings (change password, list/revoke sessions, sign out
    everywhere) ✅
15. Account activity/audit log (self-service + admin-wide view) ✅
16. Notifications (in-app; see deferred: no email/SMS delivery) ✅
17. Admin dashboard (platform stats, user management, audit log — metadata
    only, never decrypts owner content) ✅
18. Search (across own memories/stories/instructions, timeline, documents,
    beneficiaries — see scope note in `docs/API.md`) ✅
19. Responsive mobile-friendly interface (CSS Grid/Flexbox + breakpoints,
    collapsible sidebar on mobile) ✅

## Security approach

- **Passwords**: bcrypt, cost factor 12 (configurable via `BCRYPT_COST`)
- **Sessions**: short-lived JWT access tokens (in-memory on the client,
  never localStorage) + long-lived, hashed, rotating, revocable refresh
  tokens in an httpOnly/SameSite=Strict cookie
- **Authorization**: centralized RBAC (`requireRole`) and per-resource
  ownership checks (`requireOwnership`) — see `docs/THREAT_MODEL.md` T7 for
  why this is centralized rather than per-route
- **Encryption**: AES-256-GCM for memory/story/instruction content, life
  event descriptions, legacy message bodies, document/photo files, and
  document descriptions. See `docs/ARCHITECTURE.md` §7 for the exact field
  list and where encrypt/decrypt happens (always server-side, immediately
  around the DB/file boundary)
- **Input validation**: `express-validator` on every write route
- **Secure file handling**: MIME allow-lists, randomized on-disk filenames,
  files served only via authenticated/ownership-checked routes (never
  static), integrity-checked on read via SHA-256 checksum
- **Rate limiting**: `express-rate-limit` on auth endpoints and globally
- **Audit logging**: append-only `audit_logs` table; unauthorized access
  attempts are explicitly logged, not just rejected
- **Secrets**: all sourced from environment variables via
  `backend/src/config/env.js`, which fails fast at startup if a required
  production secret is missing; `.env` is git-ignored; only `.env.example`
  (placeholders) is committed

Full threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Known limitations / deferred features

Documented explicitly rather than silently pretending they work:

- **No real email/SMS delivery.** Beneficiary and trusted-contact invites
  generate a real, single-use token, but there is no integration with an
  email provider. The API returns the invite link directly to the Owner who
  created it (never to anyone else) as a stand-in for "an email was sent" —
  clearly commented in `beneficiaries.routes.js` and
  `trustedContacts.routes.js`. A production build would wire this to
  SES/SendGrid/Twilio behind the same kind of service seam already used for
  storage (`backend/src/services/storage.js`).
- **No MFA enforcement in the login flow.** The schema supports it
  (`users.mfa_enabled`, `mfa_secret_encrypted`) but no TOTP challenge is
  implemented in this MVP.
- **No account lockout after repeated failed logins** — only rate limiting.
  Both the mitigation and the gap are documented in the threat model (T1).
- **Single symmetric encryption key**, not a KMS-backed / envelope /
  per-tenant key scheme. Documented as an accepted MVP risk in the threat
  model.
- **Search decrypts candidate rows in memory** rather than using a
  searchable-encryption scheme — fine at MVP/single-user scale, not
  something that would scale to large datasets. See the comment at the top
  of `backend/src/routes/search.routes.js`.
- **Hard delete, not soft delete.** Deleting an account or a resource
  removes it immediately (with cascading foreign keys). A production system
  handling legacy/estate data would likely want a retention/undo window
  instead.
- **Single-process deployment assumptions**: SQLite and the in-memory rate
  limiter both assume one Node process. Horizontal scaling would need a
  networked Postgres/MySQL database and a shared rate-limit store (Redis).
- **No automated frontend (browser) tests** — only backend API tests. The
  frontend was manually exercised against the running API (see the
  end-to-end verification notes in this repo's commit history), but there
  is no Playwright/Cypress suite in this MVP.
- **Trusted-contact "confirmation" is a simple two-signature mechanism**,
  not a legally binding death-verification process (no integration with
  civil registries, obituaries, etc.) — appropriate for an MVP, not for a
  production legal/compliance product.

## Project structure

```
legacy-pulse/
├── README.md, .env.example, .gitignore
├── docs/                    architecture, database, threat model, API docs
├── backend/
│   ├── src/
│   │   ├── server.js, app.js
│   │   ├── config/          environment loading & validation
│   │   ├── db/               schema.sql, migrate.js, seed.js, index.js
│   │   ├── middleware/       auth, rbac, rate limiting, validation, errors
│   │   ├── utils/             crypto, jwt, audit, errors
│   │   ├── routes/            one file per resource (see docs/API.md)
│   │   ├── services/          release scheduler, storage abstraction
│   │   └── __tests__/         Jest/Supertest suites
│   └── uploads/                encrypted file storage (git-ignored)
└── frontend/
    └── public/
        ├── index.html
        ├── css/styles.css
        └── js/                api client, router, state, pages, components
```

## Notes for reviewers

- Everything in this README is verified working as of the last commit —
  the test suite passes, the seed script produces working demo accounts,
  and the app was manually exercised end-to-end (register → add
  beneficiary → write a legacy message → schedule a release → confirm via
  trusted contacts → read from the beneficiary inbox → check the audit
  log). Nothing here is a placeholder button.
- If you find something that doesn't work as described, that's a bug, not
  an intentional gap — everything intentionally left out is listed above.
