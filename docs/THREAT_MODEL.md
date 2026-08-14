# Threat Model  Legacy Pulse MVP

## Assets

1. User credentials (email + password hash)
2. Personal memories, stories, life events
3. Photos and documents
4. Legacy messages intended for beneficiaries
5. Family relationship data and access grants
6. Audit logs
7. Encryption keys

## Threat Actors

- External attacker (internet)
- Malicious or compromised beneficiary
- Compromised trusted contact
- Insider (admin or developer)
- Malicious third-party library

## Primary Threats & Mitigations

| Threat                              | Likelihood | Impact | Mitigation                                                                 |
|-------------------------------------|------------|--------|----------------------------------------------------------------------------|
| Credential stuffing / brute force   | High       | High   | Rate limiting, bcrypt, account lockout structure                           |
| Stolen JWT                          | Medium     | High   | Short expiry, refresh token rotation, logout-all                           |
| Unauthorized reading of legacy msgs | High       | Critical | Encryption + release flag + ownership checks + audit                     |
| File leakage from disk              | Medium     | High   | UUID filenames + encryption at rest + auth-gated download                  |
| Privilege escalation                | Medium     | High   | Strict RBAC + resource-level checks                                        |
| SQL injection                       | Low        | High   | Prisma parameterized queries                                               |
| XSS                                 | Medium     | Medium | React escaping, no dangerous HTML rendering in MVP                         |
| CSRF                                | Medium     | Medium | SameSite cookies / JWT in Authorization header (SPA pattern)               |
| Audit log tampering                 | Low        | High   | Append-only design; in production would use separate immutable store       |
| Key exposure                        | Low        | Critical | Env-only, never logged, validated at boot                                  |

## Trust Boundaries

1. Browser ” API (untrusted ’ trusted after auth)
2. API ” Database
3. API ” File system
4. Service layer ” Encryption keys

Sensitive operations never cross the service boundary in plaintext.

## Residual Risks

- Server-side encryption means a fully compromised backend can decrypt data.
- No hardware security module or KMS integration in MVP.
- SQLite single-file nature increases risk of complete data copy if filesystem is compromised.

These residual risks are accepted for the scope of this engineering evaluation MVP and are clearly documented.
