# Legacy Pulse V2 — Security, Cryptography & Release Engine

## A. Security Audit Summary (pre-fix)

See conversation audit. Critical issues fixed in this version:

| Severity | Issue | Status |
|----------|-------|--------|
| Critical | Global shared keys without versioning | Mitigated via envelope encryption + required MASTER_KEY |
| Critical | Keys regenerated on every restart | Fixed — startup requires MASTER_KEY_HEX |
| Critical | Broken release authorization | Fixed — state machine + owner/admin finalize rules |
| Critical | Single boolean release | Fixed — ReleaseState machine |
| High | No rate limiting | Fixed — login rate limit |
| High | CORS `*` when DEBUG | Fixed — strict origin list |
| High | Audit not integrity-protected | Mitigated — hash chain on insert |
| High | JWT without jti | Fixed — jti added |

## B. Architecture Changes (V2)

- **Envelope encryption**: `KeyProvider` abstraction → per-message DEK wrapped under master key with user context.
- **Release engine**: Explicit state machine with transitions, confirmation records, freeze flag, cancel path.
- **Audit**: SHA-256 hash chain (`prev_hash` → `entry_hash`).
- **Login**: Rate limited per email+IP.
- **Config**: Required secrets; fails closed.

## C. Cryptographic Design

```
MASTER_KEY_HEX (env / future KMS)
        │
        ▼  HKDF + AES-GCM wrap
   per-operation DEK (32 bytes, random)
        │
        ▼  AES-256-GCM (unique 12-byte nonce)
   ciphertext + tag  (stored with versioned metadata JSON)
```

- `app/core/crypto.py`: `KeyProvider`, `LocalMasterKeyProvider`, `encrypt_user_text`, `decrypt_user_text`.
- Migration: V1 data (ct+iv columns) still decryptable via legacy helpers; new writes use envelope JSON (`encryption_version=2`).
- **Not** production KMS. Swap `LocalMasterKeyProvider` for AWS/GCP/Azure KMS without changing call sites.

## D. Release State Machine

```
ACTIVE
  → INACTIVITY_DETECTED → GRACE_PERIOD
  → VERIFICATION_REQUIRED → VERIFIED → RELEASE_ELIGIBLE → RELEASE_PENDING → RELEASED
  → CANCELLED (from most non-terminal states)
  FAILED recoverable to VERIFICATION_REQUIRED
```

Terminal: RELEASED.  
Confirmations are nonce-bound, per trusted contact, invalidated on cancel.  
Owner path still multi-step internally; finalize is explicit for PENDING.

## E. Database Changes

New tables / columns:
- `release_state`, `policy_frozen`, `required_confirmations`, `encryption_version` on `legacy_messages`
- `encryption_version` on memories, media, life_events
- `release_policies`, `release_confirmations`, `release_state_transitions`
- `login_attempts`
- `audit_logs.prev_hash`, `audit_logs.entry_hash`
- `refresh_tokens.family_id`, `replaced_by`
- Life event: `status`, `source`, `verified_at`, `verified_by`, `rejection_reason`

## F. Tests (executed)

```
tests/test_auth.py (3)
tests/test_security_v2.py (12)
Total: 15 passed
```

Coverage includes: password hashing, JWT jti/tamper, envelope roundtrip, wrong-user decrypt failure, unique nonces, DEK ops, ciphertext tamper, invalid release transition, rate limit, required master key validation.

## G. Remaining Vulnerabilities (honest)

- Local master key is still a single env secret (not HSM/KMS).
- Audit hash chain is application-level; a DB admin can still rewrite the table.
- Trusted-contact confirmation identity linking is incomplete (no independent TC login).
- No MFA / step-up authentication yet.
- Frontend still uses localStorage + innerHTML (XSS risk).
- File magic-byte validation not yet implemented.
- No formal Alembic migrations (create_all only).
- SQLite for evaluation.

## H. V3 Roadmap

1. Real KMS integration behind KeyProvider
2. Independent trusted-contact authentication + signed confirmation tokens
3. MFA + step-up for beneficiary changes and release finalize
4. Magic-byte file validation + malware scanning hook
5. Alembic migrations + Postgres
6. CSP + httpOnly refresh cookies
7. External append-only audit (e.g. CloudTrail / immutable log)
8. Independent security review / pen test

## I. Verification Commands

```bash
cd pybackend
export JWT_SECRET_KEY="test-jwt-secret-key-must-be-at-least-32-chars"
export MASTER_KEY_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
export DATABASE_URL="sqlite:///:memory:"
PYTHONPATH=. python3 -m pytest tests/ -v

# Boot
cp .env.example .env   # set real secrets
PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 3001
```
