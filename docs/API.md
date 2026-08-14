# API Design

Base URL: `http://localhost:3001/api`

All protected endpoints require:
```
Authorization: Bearer <access_token>
```

## Auth

| Method | Path                    | Description                  | Auth |
|--------|-------------------------|------------------------------|------|
| POST   | /auth/register          | Create account               | No   |
| POST   | /auth/login             | Login, returns tokens        | No   |
| POST   | /auth/refresh           | Refresh access token         | No   |
| POST   | /auth/logout            | Revoke refresh token         | Yes  |
| POST   | /auth/logout-all        | Revoke all sessions          | Yes  |

## Users / Profile

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| GET    | /users/me               | Current user + profile       |
| PATCH  | /users/me               | Update profile               |
| GET    | /users/me/security      | Security settings overview   |

## Family / Beneficiaries

| Method | Path                              | Description                     |
|--------|-----------------------------------|---------------------------------|
| GET    | /family                           | List family members             |
| POST   | /family                           | Add family member / beneficiary |
| GET    | /family/:id                       | Get one                         |
| PATCH  | /family/:id                       | Update                          |
| DELETE | /family/:id                       | Remove                          |

## Memories

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| GET    | /memories               | List own memories            |
| POST   | /memories               | Create memory                |
| GET    | /memories/:id           | Get memory (decrypts if auth)|
| PATCH  | /memories/:id           | Update                       |
| DELETE | /memories/:id           | Delete                       |

## Media (Photos / Documents)

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| POST   | /media                  | Upload file (multipart)      |
| GET    | /media                  | List media                   |
| GET    | /media/:id              | Metadata                     |
| GET    | /media/:id/download     | Decrypt + stream file        |
| DELETE | /media/:id              | Delete                       |

## Life Events (Timeline)

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| GET    | /life-events            | Chronological list           |
| POST   | /life-events            | Create                       |
| PATCH  | /life-events/:id       | Update                       |
| DELETE | /life-events/:id        | Delete                       |

## Legacy Messages

| Method | Path                              | Description                          |
|--------|-----------------------------------|--------------------------------------|
| GET    | /legacy-messages                  | List own messages                    |
| POST   | /legacy-messages                  | Create (encrypts body)               |
| GET    | /legacy-messages/:id              | Get (decrypts only if authorized)    |
| PATCH  | /legacy-messages/:id              | Update                               |
| POST   | /legacy-messages/:id/release      | Manual release (owner or trusted)    |
| DELETE | /legacy-messages/:id              | Delete                               |

## Notifications

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| GET    | /notifications          | List                         |
| PATCH  | /notifications/:id/read | Mark read                    |
| POST   | /notifications/read-all | Mark all read                |

## Audit Log (Admin + Owner)

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| GET    | /audit                  | Own activity (or all if admin)|

## Admin

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| GET    | /admin/users            | List users                   |
| GET    | /admin/stats            | High-level stats             |
| PATCH  | /admin/users/:id        | Activate / deactivate        |

## Search

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| GET    | /search?q=...           | Search memories, events, messages (owner only) |

## Response Conventions

- Success: `200`, `201` with JSON body
- Validation error: `400` with Zod issues
- Unauthorized: `401`
- Forbidden: `403`
- Not found: `404`
- Rate limited: `429`

All error responses follow:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human readable",
    "details": []
  }
}
```
