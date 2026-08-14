# Legacy Pulse – Secure Digital Legacy Platform (MVP)

Engineering evaluation MVP of a production-oriented digital legacy application.

Users can securely store personal memories, photos, documents, life events, family relationships, and legacy messages. Content can be released to beneficiaries under controlled conditions. All sensitive data is encrypted at rest.

## Technology Stack

| Layer        | Technology                                      |
|--------------|-------------------------------------------------|
| Backend      | Python 3.12, FastAPI, SQLAlchemy 2, Pydantic    |
| Database     | SQLite (Prisma-compatible schema design; easy switch to PostgreSQL) |
| Auth         | JWT (access + rotating refresh), bcrypt         |
| Encryption   | AES-256-GCM (cryptography library)              |
| Frontend     | Responsive HTML + Tailwind CSS + vanilla JS     |
| File storage | Local encrypted blobs (UUID names)              |
| Tests        | pytest                                          |

## Architecture Summary

- Clean separation: config / security / models / services / API / frontend
- Encryption occurs **only** in the backend service layer
- Sensitive fields (memory content, legacy message body, notes, file content) are encrypted with AES-256-GCM before persistence
- RBAC + resource ownership checks on every sensitive endpoint
- Append-style audit logging for security-relevant actions
- Environment-driven secrets (see `.env.example`)

Full documentation lives in `/docs`:

- `ARCHITECTURE.md`
- `DATABASE.md`
- `SECURITY.md`
- `THREAT_MODEL.md`
- `API.md`

## Features Completed

- User registration & login (bcrypt + JWT + refresh token rotation)
- User dashboard & profile
- Family / beneficiary management (including trusted contacts)
- Memory creation with encryption
- Life-event timeline
- Legacy message creation, encryption, and manual release
- Photo & document upload with encryption at rest + authorized download
- Account activity / audit log
- Admin dashboard (user list + high-level stats)
- Search (title-based; content is encrypted)
- Notifications model (structure present)
- Responsive mobile-friendly UI
- Input validation (Pydantic)
- Error handling, loading/empty states in UI
- Seed / demo data
- Automated unit tests for crypto & auth primitives
- `.env.example`, clear comments on architectural decisions

## Features Intentionally Deferred

- Real email / push notification delivery (structure only)
- Advanced conditional release (e.g. verified death certificate)
- Multi-factor authentication
- Client-side / end-to-end encryption
- Cloud object storage (S3 + KMS)
- Scheduled background job runner for time-based release (logic is present; cron-style job not wired)
- Full beneficiary invitation + independent login flow (owner-centric for MVP)

## Known Limitations

- Server-side encryption: a fully compromised backend can decrypt data
- SQLite is used for zero-ops evaluation; production should use PostgreSQL
- No formal rate-limiting middleware beyond basic design notes (easy to add with `slowapi`)
- File storage is local; not suitable for multi-instance deployment without shared storage
- Search cannot index encrypted content bodies

## Running Locally

```bash
cd pybackend

# Optional: create virtualenv
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# Copy environment file and (optionally) generate strong keys
cp .env.example .env
# Edit .env if desired – defaults work for local demo

# Start the API + frontend
uvicorn app.main:app --host 0.0.0.0 --port 3001 --reload
```

Open http://localhost:3001

API docs: http://localhost:3001/api/docs

## Demo Credentials

| Role  | Email                     | Password    |
|-------|---------------------------|-------------|
| Owner | alex@legacypulse.demo     | Legacy123!  |
| Admin | admin@legacypulse.demo    | Admin123!   |

Demo data includes sample memories, a life event, family members, and a sealed legacy message.

## Testing

```bash
cd pybackend
pytest tests/ -v
```

## Security Notes (What is encrypted & where)

| Data                        | Algorithm     | Key                     | Location of encrypt/decrypt |
|-----------------------------|---------------|-------------------------|-----------------------------|
| Legacy message body         | AES-256-GCM   | DATA_ENCRYPTION_KEY     | `app/core/security.py` + service layer |
| Memory content              | AES-256-GCM   | DATA_ENCRYPTION_KEY     | same                        |
| Life-event description      | AES-256-GCM   | DATA_ENCRYPTION_KEY     | same                        |
| Family notes                | AES-256-GCM   | DATA_ENCRYPTION_KEY     | same                        |
| Uploaded file content       | AES-256-GCM   | FILE_ENCRYPTION_KEY     | same                        |
| Passwords                   | bcrypt        | N/A                     | `security.py`               |
| Refresh tokens              | SHA-256       | N/A                     | `security.py`               |

Keys are loaded from environment variables and never appear in source control.

## Repository

Repository name used: `legacy-pulse-kimi-engineering-test`

No secrets, real `.env`, or credentials are committed.
