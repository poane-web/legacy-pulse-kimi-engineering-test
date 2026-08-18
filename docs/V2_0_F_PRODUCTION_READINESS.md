# Legacy Pulse V2 — Checkpoint V2.0-F: Production Readiness

**This document exists to say plainly what V2.0-A through V2.0-E did NOT
solve.** Passing 102/102 tests, or all of V2.0-A–E's fixes being real and
verified, does not make this application production-ready. Production
readiness is mostly an infrastructure and operations question, not an
application-code question — most of what's listed below cannot be fixed
by writing more code in this repository; it requires real infrastructure
this MVP was never given.

## What this checkpoint DID add (application-layer, verified)

These are the only V2.0-F items that are actual code changes, because
they're the subset of "production readiness" achievable without external
infrastructure:

1. **Graceful shutdown** (`backend/src/server.js`): `SIGTERM`/`SIGINT`
   now stop the cron scheduler, close the HTTP server (finishing in-flight
   requests, refusing new ones), close the DB connection, and exit
   cleanly — with a 10s force-exit safety net. **Verified live**, not
   just written: started a real server process, sent it a real `SIGTERM`,
   and confirmed the exact log sequence (`shutting down gracefully` →
   `Database connection closed` → clean process exit) actually happens.
   Without this, every container orchestrator restart/deploy would kill
   requests mid-flight and leave the SQLite WAL file in an arbitrary
   state.
2. **Health check now verifies DB connectivity** (`GET /api/health`),
   returning `503` (not `200`) if the database can't be queried — meaningful
   for an orchestrator's liveness/readiness probe, which should stop
   routing traffic to an instance whose DB connection is broken even if
   the process itself is still technically running. 2 new tests, including
   a genuine connection-failure scenario (not mocked).
3. **Reference `Dockerfile` + `docker-compose.yml`**: multi-stage build,
   non-root runtime user, no baked-in secrets, healthcheck directive. **Not
   verified by an actual container build** — Docker was not available in
   the environment this project was built in. The path resolution logic
   was reasoned through carefully and is documented inline, but this is
   explicitly flagged as unverified rather than claimed as tested.

Everything else below is a gap, not a fix.

## Gaps requiring real infrastructure (not fixable by more application code)

### Secrets & key management
- **No KMS / envelope encryption.** `DATA_ENCRYPTION_KEY` is a single
  symmetric key from an environment variable. A real deployment needs a
  managed KMS (AWS KMS, GCP Cloud KMS, HashiCorp Vault) with envelope
  encryption (a data-encryption-key per tenant/record, wrapped by a
  KMS-held key-encryption-key), so a leaked application-server env var
  doesn't equal "attacker can decrypt the entire database."
- **No live key rotation.** V2.0-C's versioned ciphertext format
  (`docs/V2_0_C_PLAN.md`) makes rotation *architecturally possible* in the
  future — but no rotation mechanism, re-encryption job, or multi-key-ID
  support was actually built.
- **No managed secrets store.** `.env` files are fine for local
  development; production needs AWS Secrets Manager / GCP Secret Manager
  / Vault, with secrets injected at runtime and rotated independently of
  deploys.

### File storage
- **Uploads are local disk** (`backend/uploads/`). This does not survive
  a container restart without a persistent volume, does not scale past
  one instance without a shared filesystem, and has no built-in
  durability/replication guarantees. A real deployment needs S3/GCS/Azure
  Blob (with either server-side encryption or the same application-layer
  AES-256-GCM approach applied to objects instead of local files — the
  `services/storage.js` seam exists specifically so this swap doesn't
  touch route code).

### Database
- **SQLite is single-file, single-process.** Fine for this MVP's
  evaluation purposes; wrong for any real multi-instance deployment. A
  production system needs a networked database (Postgres is the natural
  choice given this schema's shape) with real concurrent-write handling,
  replication, and point-in-time recovery. This also affects V2.0-D's
  "no distributed lock" caveat and the rate limiter (see below).
- **No connection pooling / read replicas** — not applicable to SQLite,
  but will be a real design decision once migrated to a networked DB.

### Horizontal scaling
- **Rate limiting is in-memory, per-process.** `express-rate-limit`'s
  default store means running two instances of this app gives an
  attacker roughly double the effective rate limit, since each instance
  tracks independently. Needs a shared store (Redis) for the limiter to
  mean anything once there's more than one process.
- **The cron release-scheduler runs in every process.** With N instances,
  N processes independently sweep for due messages. V2.0-D's idempotency
  guarantees (`releaseMessage`'s `WHERE status = 'pending'` guard) mean
  this doesn't cause *incorrect* releases, but it is wasted, uncoordinated
  work at scale. A production deployment should run the scheduler as a
  single dedicated worker/cron job, not embedded in every web process.

### Authentication & identity
- **MFA has no recovery-code mechanism** (flagged in V2.0-C): a user who
  loses their authenticator device and their password has no self-service
  path back into their account. Needs either backup codes (generated at
  MFA-enable time, single-use, stored hashed) or an admin-assisted
  recovery flow with its own audit trail.
- **No managed identity/MFA provider integration** (Okta, Auth0, Duo) —
  this MVP's TOTP is fully self-hosted application logic. Fine for an
  MVP; an enterprise deployment may need SSO/SAML/OIDC federation this
  app has no support for at all.
- **No password-breach checking** (e.g. Have I Been Pwned's k-anonymity
  API) at registration/password-change time.

### Observability
- **No structured logging.** `morgan`'s dev/combined format is
  human-readable console output, not machine-parseable JSON a log
  aggregator (Datadog, CloudWatch Logs, ELK) can index and query
  effectively.
- **No metrics.** No request-rate/error-rate/latency instrumentation
  (Prometheus-style `/metrics` endpoint or equivalent), no dashboards, no
  SLO tracking.
- **No error tracking service** (Sentry or equivalent) — the central
  error handler logs to stdout only; there's no aggregation, alerting, or
  stack-trace-with-context capture across instances.
- **No distributed tracing** — not that it's needed yet at this
  complexity, but worth naming as absent.
- **No alerting** on any of the above — nobody gets paged if the release
  scheduler stops running, if the error rate spikes, or if the database
  becomes unreachable (beyond the health check reporting `503` to
  whatever's polling it, if anything is).

### Backups & disaster recovery
- **No automated backups of the SQLite file or the uploads directory.**
  A disk failure or accidental `rm` loses everything with zero recovery
  path.
- **No defined RPO/RTO** (Recovery Point Objective / Recovery Time
  Objective) — nobody has decided how much data loss or downtime is
  acceptable, which is a prerequisite for designing a real backup
  strategy, not an afterthought.
- **`audit_logs` retention** was flagged in V2.0-C (M6) as a compliance
  decision, not a mechanical one, and remains undecided — how long should
  account-activity history be kept, and does that answer differ by
  jurisdiction (GDPR's data minimization principle vs. security/legal
  retention needs)?

### Compliance & legal
- **No data residency controls** — where is data physically stored, and
  does that match what's promised to users in any jurisdiction with
  residency requirements?
- **No formal privacy policy / terms of service enforcement** in the
  application itself (account deletion exists and is real — the V1
  cascading delete — but broader GDPR "right to be forgotten" /
  data-export obligations haven't been scoped).
- **No legal review of the "digital legacy" concept itself** — estate law,
  what happens to an account after a real death (not just the app's
  "trusted contact confirmation," which is explicitly NOT a legally
  binding death-verification process — flagged in `docs/THREAT_MODEL.md`
  since V1), and jurisdiction-specific inheritance/data-ownership rules
  are genuinely outside this project's scope and need actual legal
  expertise, not more code.

### Testing & assurance
- **No penetration testing.** Every fix in V2.0-A through V2.0-E was
  self-audited and self-verified (with real, run tests and, where
  practical, live-server reproduction) — that is meaningfully different
  from an independent, adversarial security review by someone who didn't
  write the code. A real production launch needs one.
- **No load/performance testing.** Nobody has measured this app's actual
  throughput, latency under load, or the point at which SQLite's
  single-writer model becomes a bottleneck.
- **No fuzz testing** of file upload handling, JSON body parsing, or the
  TOTP verification endpoint.
- **No dependency vulnerability scanning wired into CI** (e.g.
  `npm audit` / Snyk / Dependabot as a gate, not a manual check — `npm
  audit` was run manually during development and came back clean, but
  there's no ongoing automated check).
- **No CI/CD pipeline at all.** Tests exist and pass; nothing runs them
  automatically on every push/PR, and there's no automated deploy
  pipeline with staging/production gating.

### TLS / network
- **The application does not terminate TLS.** It assumes a reverse
  proxy/load balancer/platform (nginx, an ALB, Cloudflare, etc.) handles
  HTTPS termination in front of it. This is a normal and reasonable
  architecture, but it needs to actually be configured — this app running
  standalone on port 4000 serves plain HTTP.
- **`TRUST_PROXY` (V2.0-C) defaults to `false`**, which is correct until
  that reverse proxy exists, at which point it MUST be reconfigured (see
  `.env.example`) or rate limiting and audit-log IPs silently become
  wrong/spoofable.

## What IS true, and can be claimed

- Every fix from V2.0-A through V2.0-E is real, was implemented against
  actual code (not hypothetically described), and was verified — by an
  automated regression test in nearly every case, and by manual live-server
  reproduction for the highest-stakes ones (H1's token revocation, H3's
  release-on-creation fix, this checkpoint's graceful shutdown).
- 102/102 automated tests pass, covering encryption correctness (including
  official RFC 6238 vectors), authentication/authorization/IDOR,
  CSRF/file-upload/rate-limiting defenses, the release state machine's
  atomicity, and data-model integrity.
- The codebase is meaningfully more secure and more architecturally sound
  than the V1 baseline the original audit was run against.
- **None of that is the same claim as "ready to hold real people's real
  sensitive legacy data in production."** That claim requires everything
  in this document to be addressed, most of it by people and systems
  outside this codebase.

## Exact commands to reproduce this checkpoint's verified changes

```bash
cd backend
npm install
cp ../.env.example .env
npm run migrate
npm test   # expect 102/102 passing, including v2f_healthCheck.test.js
```

To manually re-verify graceful shutdown (what was actually run to
validate this checkpoint):

```bash
npm start &
SERVER_PID=$(pgrep -f "src/server.js")
curl -s http://localhost:4000/api/health   # expect {"status":"ok",...,"db":"connected"}
kill -TERM $SERVER_PID
# Expect, in order, in the server's stdout:
#   [server] Received SIGTERM, shutting down gracefully...
#   [server] Database connection closed. Exiting.
# and the process to actually exit (check with: ps aux | grep server.js)
```
