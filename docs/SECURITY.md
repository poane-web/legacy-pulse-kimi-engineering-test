# Security Architecture

## 1. Authentication

- **Password storage**: bcrypt with cost factor 12.
- **Tokens**:
  - Access token: JWT (HS256), 15-minute expiry, contains `sub` (userId), `role`, `email`.
  - Refresh token: opaque random 32-byte value, stored as SHA-256 hash in DB, 7-day expiry.
- Refresh tokens are rotated on use and can be revoked.
- Login attempts are rate-limited (5 attempts / 15 min per IP + email).

## 2. Authorization Model (RBAC + Resource Checks)

Roles:
- `USER`  owner of their own data
- `ADMIN`  full system access + audit visibility
- `BENEFICIARY`  can only view content that has been explicitly released to them
- `TRUSTED_CONTACT`  can trigger manual release of content for the owner (with audit)

Every request that touches content performs:
1. Authentication (valid JWT)
2. Role check
3. Ownership or explicit access grant check

## 3. Encryption

### Data at Rest (Database)
Sensitive text fields are encrypted with **AES-256-GCM** before being written to the database.

Key: `DATA_ENCRYPTION_KEY` (32-byte hex or base64, loaded from environment).

Encryption occurs inside the service layer. The Prisma models store ciphertext + IV + auth tag.

### Files at Rest
Uploaded photos and documents are encrypted with a separate key (`FILE_ENCRYPTION_KEY`) using AES-256-GCM before being written to the `uploads/` directory under a random UUID filename. Original name and MIME type are stored in the database only.

### Key Management
- Keys never appear in source code or git.
- Keys are required via environment variables and validated at startup.
- In production, keys should be managed by a secrets manager (AWS KMS, HashiCorp Vault, etc.).

## 4. Secure File Handling

- Files are never served directly from disk.
- Download endpoints decrypt on-the-fly after authorization checks.
- Filename on disk is a UUID; original name is metadata only.
- Size and MIME type are validated on upload (max 10 MB for MVP).

## 5. Input Validation

- All request bodies validated with **Zod** schemas.
- File type whitelist (images + common document types).
- SQL injection is prevented by Prisma parameterized queries.
- XSS is mitigated by Reacts default escaping + careful handling of any HTML content (MVP stores plain text).

## 6. Audit Logging

Every sensitive operation writes an immutable `AuditLog` record containing:
- actorId
- action
- resourceType + resourceId
- IP address
- user agent
- timestamp
- optional metadata

Admin dashboard can view the audit trail.

## 7. Session / Token Security

- JWTs are short-lived.
- Refresh tokens are hashed at rest and can be revoked individually or en masse (logout-all).
- Tokens are sent only over HTTPS in production (enforced by configuration).

## 8. Rate Limiting

- Auth endpoints: strict limits.
- Write endpoints: moderate limits.
- Implemented with `express-rate-limit`.

## 9. Secrets Handling

- All secrets live in `.env` (never committed).
- `.env.example` documents every required variable without real values.
- Application refuses to start if required secrets are missing.

## 10. Protection Against Unauthorized Beneficiary Access

- Content is only returned if `isReleased === true` **or** the requester is the owner.
- Scheduled release is checked by a background job (or on-demand evaluation).
- Trusted contacts can only release, not read, until release occurs (depending on configuration).

## 11. Known Security Limitations of the MVP

- No multi-factor authentication.
- No client-side encryption (server can theoretically decrypt).
- Local file storage instead of object storage with KMS.
- SQLite does not offer the same isolation guarantees as a properly configured PostgreSQL deployment.
- No formal penetration testing performed.

These are explicitly documented rather than claimed as production-hardened.
