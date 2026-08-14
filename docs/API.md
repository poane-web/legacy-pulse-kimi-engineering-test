# Legacy Pulse — API Reference

Base URL: `http://localhost:4000/api`
All request/response bodies are JSON. Authenticated routes require header
`Authorization: Bearer <accessToken>` unless noted.

Standard error shape:
```json
{ "error": { "message": "Human readable message", "code": "OPTIONAL_CODE" } }
```

## Auth
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /auth/register | none | Create an owner account |
| POST | /auth/login | none | Returns `accessToken`, sets refresh cookie |
| POST | /auth/refresh | refresh cookie | Rotates refresh token, returns new access token |
| POST | /auth/logout | refresh cookie | Revokes refresh token, clears cookie |
| GET | /auth/me | bearer | Current user profile summary |

## Users / Profile
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /users/profile | bearer | Get own profile |
| PUT | /users/profile | bearer | Update profile fields |
| PUT | /users/password | bearer | Change password (requires current password) |
| DELETE | /users/me | bearer | Delete own account and all owned data (cascades) |

## Beneficiaries
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /beneficiaries | bearer(owner) | List own beneficiaries |
| POST | /beneficiaries | bearer(owner) | Create + generate invite token |
| PUT | /beneficiaries/:id | bearer(owner), ownership | Update relationship/name |
| DELETE | /beneficiaries/:id | bearer(owner), ownership | Revoke a beneficiary |
| POST | /beneficiaries/claim | none | Beneficiary claims invite via token during registration |

## Trusted Contacts
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /trusted-contacts | bearer(owner) | List own trusted contacts |
| POST | /trusted-contacts | bearer(owner) | Add trusted contact + invite token |
| DELETE | /trusted-contacts/:id | bearer(owner), ownership | Revoke |
| POST | /trusted-contacts/confirm/:ownerId | bearer(linked contact) | Confirm release-trigger event for an owner |

## Memories / Stories / Instructions
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /memories?type=memory\|story\|instruction | bearer(owner) | List own, decrypted |
| POST | /memories | bearer(owner) | Create (encrypted server-side) |
| GET | /memories/:id | bearer(owner), ownership | Read one |
| PUT | /memories/:id | bearer(owner), ownership | Update |
| DELETE | /memories/:id | bearer(owner), ownership | Delete |

## Life Events (Timeline)
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /timeline | bearer(owner) | List, sorted by event_date |
| POST | /timeline | bearer(owner) | Create |
| PUT | /timeline/:id | bearer(owner), ownership | Update |
| DELETE | /timeline/:id | bearer(owner), ownership | Delete |

## Documents
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /documents | bearer(owner) | List metadata (no content) |
| POST | /documents | bearer(owner), multipart | Upload; encrypts file to disk |
| GET | /documents/:id/download | bearer(owner), ownership | Decrypts and streams file |
| DELETE | /documents/:id | bearer(owner), ownership | Delete file + row |

## Photos
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /photos | bearer(owner) | List metadata |
| POST | /photos | bearer(owner), multipart | Upload (image types only) |
| GET | /photos/:id/download | bearer(owner), ownership | Decrypts and streams |
| DELETE | /photos/:id | bearer(owner), ownership | Delete |

## Legacy Messages
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /legacy-messages | bearer(owner) | List own authored messages (metadata + decrypted body since owner is author) |
| POST | /legacy-messages | bearer(owner) | Create; body encrypted server-side |
| PUT | /legacy-messages/:id | bearer(owner), ownership | Update (only while `status = pending`) |
| DELETE | /legacy-messages/:id | bearer(owner), ownership | Revoke/delete (only while `pending`) |
| GET | /legacy-messages/inbox | bearer(beneficiary) | List messages addressed to the caller that are `released` |
| GET | /legacy-messages/:id/read | bearer(beneficiary), release-check | Decrypt & return one released message addressed to caller |

## Admin
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /admin/stats | bearer(admin) | Aggregate counts (users, messages, storage used) |
| GET | /admin/users | bearer(admin) | List users, metadata only |
| PUT | /admin/users/:id/status | bearer(admin) | Enable/disable an account |
| GET | /admin/audit-logs | bearer(admin) | Paginated audit log |

## Search
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /search?q=... | bearer(owner) | Searches own memories, life events, documents (by decrypted title/tags for memories, filename for documents — see README for search scope/limits) |

## Notifications
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /notifications | bearer | List own notifications |
| PUT | /notifications/:id/read | bearer, ownership | Mark read |

## Audit (self-service)
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /audit/me | bearer | Own account activity log |

## Security Settings
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /security/sessions/revoke-all | bearer | Revoke all refresh tokens (sign out everywhere) |
| GET | /security/sessions | bearer | List active (non-revoked, unexpired) sessions |
