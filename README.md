# SentinelASM

<p align="right"><sup><a href="#license">MIT licensed</a></sup></p>

SentinelASM is an **open-source attack-surface-management (ASM) platform** for a
single organisation (multi-tenant ready): you register your domains, complete a
DNS-TXT ownership check, and the platform then enumerates subdomains, ports,
DNS records, SSL/TLS and WHOIS metadata around them on a schedule, synthesises
findings from that life cycle, scores and enriches them against CISA KEV and
OSV data, and pushes what matters to webhooks and email digests — all behind a
 tenants-scoped `/api/v1` REST surface and a React dashboard.

## Screenshots

*Staged via `scripts/seed_demo.py` (FIXTURE data only, no network) into a
`demo_` DB — then capture from `http://localhost:5173`. Placeholder until the
maintainer commits the capture.*

<!-- 🚧 Screenshot placeholder dashboard -->
![Dashboard](docs/screenshots/dashboard.png) <!-- Dashboard.tsx -->
<!-- 🚧 Screenshot placeholder asset-detail (d3 graph) -->
![Asset](docs/screenshots/asset-detail.png) <!-- AssetDetail.tsx -->
<!-- 🚧 Screenshot placeholder scans -->
![Scans](docs/screenshots/scans.png) <!-- Scans.tsx -->
<!-- 🚧 Screenshot placeholder findings -->
![Findings](docs/screenshots/findings.png) <!-- Findings.tsx -->
<!-- 🚧 Screenshot placeholder alerting -->
![Alerting](docs/screenshots/alerting.png) <!-- Alerting.tsx -->
<!-- 🚧 Screenshot placeholder reports -->
![Reports](docs/screenshots/reports.png) <!-- Reports.tsx -->
<!-- 🚧 Screenshot placeholder two-factor-setup -->
![Security](docs/screenshots/two-factor-setup.png) <!-- TwoFactorSetup.tsx -->

Capture list (pages under `frontend/src/pages/`): `Dashboard`, `Assets`,
`AssetDetail` (graph), `Scans`, `ScanPolicies`, `Findings`, `FindingDetail`,
`Alerting`, `Reports`, `Organizations`, `Settings`, `TwoFactorSetup`,
`Login` + `Register`.

## Architecture

```mermaid
flowchart TD
    subgraph EDGE["/docker-compose (single host, read-only rootfs, non-root)"]
        BROWSER["React SPA<br/>Vite + TypeScript"]
        NGINX["nginx-unprivileged 8080<br/>TLS-ready edge, /metrics → 404"]
        API["FastAPI + slowapi limiter<br/>auth · assets · scans · findings · reports"]
        WORKER["Celery worker<br/>queue 'scans' + DLQ"]
        BEAT["Celery Beat<br/>scan policies · email digests"]
    end
    PG[(PostgreSQL 16)]
    RD[(Redis 7<br/>requirepass — broker + rate limits + lockout)]
    KEV["CISA KEV cache<br/>named volume /kev-cache"]
    MAIL["OSV + external intel"]
    WEB["Slack/Discord/Jira webhooks<br/>+ SMTP digest"]

    BROWSER -->|HTTP| NGINX
    NGINX -->|/api/* /health| API
    NGINX -->|"/* (SPA)"| BROWSER
    API --> PG
    API --> RD
    WORKER --> RD
    WORKER --> PG
    WORKER --> KEV
    BEAT --> RD
    WORKER -->|enrichment| MAIL
    WORKER -->|alerts| WEB
    API -.->|"/metrics gated"| PROM["Prometheus scraper<br/>token or CIDR required"]
```

## Feature status

| Capability | Status | Notes |
|------------|--------|-------|
| Domain ownership verification (DNS-TXT) | ✅ works | Block scans until verified; expiry + recheck scheduling |
| Subdomain / port / DNS / SSL / WHOIS enumeration | ✅ works | Celery pipeline w/ retries + DLQ; per-target enrichment timeouts |
| Discovery sources: crt.sh CT logs + bounded DNS brute-force | ✅ works | crt.sh passive; DNS brute-force is **active** and scope-gated; per-source cap + truncation surfaced |
| Email-security discovery (SPF/DKIM/DMARC/MTA-STS/BIMI) | ✅ works | Passive DNS-only lookups; mail-evidence gating; findings with confidence + remediation |
| Subdomain takeover (CNAME → claimable provider) | ✅ works | Passive DNS + active HTTP confirmation of dangling CNAMEs; mail-evidence gating; findings with confidence + remediation |
| Optional key-based enrichment providers (Shodan/Censys/etc.) | 🔜 planned | Provider management API + Fernet-encrypted keys; no provider implementation shipped yet |
| Findings + risk scoring (KEV/OSV, age, exposure) | ✅ works | KEV cached to disk (named volume in compose); OSV configurable |
| Scan policies (cron / periodic) | ✅ works | Celery Beat + `run-now`; per-org policies |
| RBAC (viewer/analyst/admin, 10 permissions) | ✅ works | Enforced per-route; tenant matrix test suite |
| JWT + refresh rotation, session family burn | ✅ works | Password change revokes siblings, keeps caller |
| TOTP 2FA + recovery codes | ✅ works | pyotp, lockout-aware; recovery codes hashed |
| Login lockout + admin unlock | ✅ works | Per-account/IP exponential backoff, capped 15 min |
| Alerting: webhooks + email digests | ✅ works | Credentials Fernet-encrypted; digest needs SMTP |
| Reports (5 CSV + 2 PDF) | ✅ works | fpdf2; graceful error if missing |
| Asset graph (d3) | ✅ works | `/assets/{id}/graph` |
| Prometheus `/metrics` | ✅ works | Deny-by-default (token or CIDR); nginx 404s at edge |
| Edge security headers | ✅ works | CSP + `frame-ancestors 'none'` + X-Frame-Options on the SPA; nosniff + Referrer-Policy everywhere; HSTS in the TLS block; `server_tokens off` |
| API keys (scoped, hashed, expiry) | ✅ works | Intersect-only, never expand role |
| Audit log of privileged actions | ✅ works | Written on sensitive endpoints |
| Real-time scan progress (WebSocket) | ✅ works | WebSocket (`GET /scans/{id}/ws`) with SSE + polling fallback; reconnect + heartbeat. Authenticated, tenant-scoped, org-checked. |
| SSO / SCIM | 🔜 planned | Roadmap |
| Postgres row-level security (RLS) | 🔮 deferred to first SaaS-scale run | Design only — `docs/rls-design.md` |
| Email digests without SMTP configured | ⚠️ partial | Configuration-dependent; fails "closed" with error mail state |

## Tech stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, TypeScript 5.9, Vite 5, Tailwind CSS 3, Recharts 2, d3 7, Axios (per-route chunks, ≤ ~360 kB each, ≤ ~250 kB initial) |
| **Backend** | FastAPI 0.136.3 (pinned), SQLAlchemy 2.1, Alembic, Pydantic v2, slowapi |
| **Database** | PostgreSQL 16 |
| **Auth** | PyJWT 2.15.1 HS256, bcrypt, pyotp 2.10 (TOTP), scoped API keys |
| **Task queue** | Celery 5 (retries, DLQ, Beat) |
| **Infra** | Docker Compose (hardened: non-root, read-only rootfs, cap-drop ALL, no-new-privileges) |
| **Report** | fpdf2 ≥ 2.7 (PDF), stdlib csv (Excel-friendly CSV) |
| **Observability** | prometheus-client |

## Repository layout

```
.
├── backend/
│   ├── api/…                    # legacy HTTP routes (kept for compatibility)
│   ├── app/
│   │   ├── api/v1/              # v1 REST surface (auth, assets, scans, …)
│   │   ├── core/                # config, errors, permissions, SSRF pinning
│   │   └── db/                  # session, engine
│   ├── models/                  # SQLAlchemy models (tenant-scoped)
│   ├── services/                # discovery, findings, scoring, alerts
│   ├── tasks/                   # Celery tasks (discovery, scheduler)
│   ├── workers/                 # Celery app + DLQ wiring
│   ├── migrations/              # Alembic
│   └── tests/                    # ≈586 characterization tests (v3 suite)
├── frontend/
│   └── src/
│       ├── pages/               # Dashboard, Assets, Scans, Findings, …
│       ├── lib/api.ts           # Typed axios client for /api/v1
│       ├── contexts/            # AuthContext
│       └── components/…         # MfaStep, RecoveryCodesDisplay, layout
├── docker-compose.yml            # Hardened single-host stack
├── docs/                         # ARCHITECTURE, OPERATIONS, API, threat-model, rls-design
├── scripts/                      # db_guard, bootstrap, seed_demo, unlock/reset/encrypt
├── nginx/nginx.conf              # Edge proxy (unprivileged)
└── README.md
```

## Quickstart

Prereqs: Python 3.13, Node 20, PostgreSQL 16 + Redis 7 running locally,
and `uv` (`pip install uv`). Docker-only is simpler — skip to the compose
alternative at the end. **Prefer a scratch DB; `scripts/db_guard.sh` refuses
anything not named `scratch_*` or `demo_*`.**

> The sequence below was executed end-to-end in a fresh clone (`uv sync` →
> `db_guard` OK → `alembic upgrade head` → `/health` 200 → register returns
> tokens). It is tested, not aspirational.

### Local dev

```bash
# 1 — env files (idempotent; never overwrites existing .env)
make setup

# 2 — scratch database (never the dev DB `sentinelasm`)
psql -h localhost -U postgres -c "CREATE USER sentinel WITH PASSWORD 'sentinelpass';"   # first time only
psql -h localhost -U postgres -c "CREATE DATABASE scratch_dev OWNER sentinel;"
DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/scratch_dev \
  bash scripts/db_guard.sh          # → "OK (scratch database)"

# 3 — backend (locked deps: backend/uv.lock is hash-verified)
cd backend
uv sync --frozen --group dev        # creates .venv
cd ..

# 4 — migrate + run (DATABASE_URL targets the scratch DB)
DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/scratch_dev make migrate
DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/scratch_dev \
  REDIS_URL=redis://localhost:6379/15 make dev    # http://localhost:8000

# 5 — celery worker (separate terminal, from backend/)
cd backend
DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/scratch_dev \
  REDIS_URL=redis://localhost:6379/15 .venv/bin/celery -A workers.celery_app:celery worker -l info -Q scans,celery

# 6 — frontend (separate terminal)
cd ../frontend
npm ci                                # installs exactly package-lock.json
npm run dev                           # http://localhost:5173
```

Register via the UI or API (`email` must be a valid address; nothing is sent
anywhere without SMTP configured):

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","email":"demo@example.com","password":"Str0ng-pass-2026","organization":"Local Demo"}'
# → {"access_token": …, "refresh_token": …}
```

### Screenshots / demo data

```bash
psql -h localhost -U postgres -c "CREATE DATABASE demo_local OWNER sentinel;"
DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/demo_local make migrate
DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/demo_local \
  backend/venv/bin/python scripts/seed_demo.py     # FIXTURE data only, no network
```

The seeder refuses anything not named `demo_*`/`scratch_*` (db_guard rule),
then creates one demo org, an admin user (`demo` with a **random password
printed once to the terminal** — record it when you see it; lose it and you
reseed), 2 assets, 5 findings, alerts, an alert integration and scan history
from `scripts/seed_demo.py`'s FIXTURE objects.

### Docker compose (full stack on http://localhost)

```bash
make setup      # generates JWT_SECRET + POSTGRES_PASSWORD + REDIS_PASSWORD (never printed)
make up         # runs postgres/redis/backend/worker/beat/frontend/nginx; all health-checked
```

## Configuration

All backend configuration lives in `backend/.env` for local dev and
root `./.env` for compose (copy from `.env.example`, then `make setup`),
which are also the surfaces the drift-test below enforces. Every variable
must be present in `.env.example` — a test enforces that adding a new
Settings field without documenting it fails `make check`.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `DATABASE_URL` | `postgresql://sentinel:sentinelpass@localhost:5432/sentinelasm` | Yes | SQLAlchemy connection string |
| `REDIS_URL` | `redis://:PASSWORD@redis:6379/0` (compose) / `redis://localhost:6379/0` (dev) | Yes | Celery broker + token blacklist |
| `REDIS_PASSWORD` | — (generated) | Compose: **Yes** | Redis `--requirepass`; generated by `scripts/bootstrap.sh`, embedded into `REDIS_URL`, never printed |
| `JWT_SECRET` | — | **Yes** | HS256 signing key; app **refuses to start** without one |
| `SECRETS_ENCRYPTION_KEY` | — | **Yes** | Comma-separated Fernet key list for secrets at rest; first encrypts, all decrypt (rotation) |
| `JWT_ALGORITHM` | `HS256` | No | |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | No | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | No | Refresh token lifetime |
| `ENVIRONMENT` | `development` (`production` in compose example) | No | `production` rejects `DEBUG=True` + default DB URL |
| `DEBUG` | `True` (local example; `False` in compose) | No | `True` also enables Celery eager mode |
| `APP_NAME` | `SentinelASM` | No | |
| `CORS_ORIGINS` | (empty) | No | Extra `<scheme>://<host>` entries allowed for CORS; empty = same-origin only |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` | (empty) / `587` | No | Required for password-reset emails and digest delivery |
| `FRONTEND_URL` | `http://localhost:5173` | No | Used in password-reset links |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `60` | No | Global API limiter budget |
| `RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE` | `10` | No | Tighter cap on login/register/reset endpoints |
| `RATE_LIMIT_SCAN_REQUESTS_PER_MINUTE` | `5` | No | Cap on scan-trigger endpoint (dense abuse vector) |
| `RATE_LIMIT_FAIL_CLOSED` | `true` | No | When Redis is unreachable, reject every request with 429 (fail-closed) instead of failing open. Health checks stay exempt. |
| `OSV_API_URL` / `OSV_TIMEOUT_SECONDS` / `OSV_ENABLED` | `https://api.osv.dev/v1/query` / `10.0` / `True` | No | CVE enrichment feed |
| `KEV_CACHE_DIR` | (empty → `/tmp`) | No | CISA KEV cache dir; compose sets `/kev-cache` named volume (rootfs is read-only) |
| `WEBHOOK_ALLOWED_PORTS` | `443,8443` | No | Ports Slack/Discord/Jira deliveries may target (save + send enforced) |
| `TRUSTED_PROXIES` | (empty) | No | CIDRs allowed to set X-Forwarded-For; compose sets `172.28.0.0/16` (fixed `sentinelnet` subnet for bundled nginx) |
| `RETENTION_ALERT_DAYS` / `RETENTION_SCAN_HISTORY_DAYS` / `RETENTION_AUDIT_LOG_DAYS` / `RETENTION_SNAPSHOT_KEEP_NEWEST` / `RETENTION_BATCH_LIMIT` | `90` / `180` / `365` / `50` / `1000` | No | Daily beat purge: alerts/scan-history/audit-logs older than the window go; `asset_snapshots` keep the newest N per asset (newest never deleted); batch cap per table per run (0 = unlimited) |
| `METRICS_BEARER_TOKEN` | (empty) | No | Bearer token admitted to `/metrics` (generated by bootstrap.sh) |
| `METRICS_ALLOWED_CIDRS` | `127.0.0.1/32` | No | Peer CIDRs admitted to `/metrics` without a token |
| `LOGIN_MAX_ATTEMPTS` | `5` | No | Failed logins before lockout engages |
| `LOGIN_ATTEMPT_WINDOW_SECONDS` | `300` | No | Sliding window for counting failures |
| `LOGIN_LOCKOUT_BASE_SECONDS` | `60` | No | First lock duration; doubles per engagement |
| `LOGIN_LOCKOUT_MAX_SECONDS` | `900` | No | Cap on lock duration |
| `SCAN_EVENTS_STREAM_MAXLEN` | `200` | No | Approximate MAXLEN of the `scan:{id}:events` Redis Stream (trimming is approximate and best-effort; the 24 h TTL below always applies) |
| `SCAN_EVENTS_EXPIRE_SECONDS` | `86400` | No | TTL (24 h) refreshed on every published scan event |
| `SCAN_STREAM_HEARTBEAT_SECONDS` | `15` | No | `: heartbeat` cadence inside an open stream; heartbeats are bytes of the already-counted request and never rate-limit again |
| `SCAN_STREAM_MAX_PER_USER` | `5` | No | Per-user concurrent open scan streams; exceeding answers 429 `stream_cap_reached` (slot released in `finally` including on client disconnect; each slot carries its own expiry score = open + max duration + margin, pruned on every open, so a killed API process cannot leak the cap) |
| `SCAN_STREAM_MAX_DURATION_SECONDS` | `900` | No | Maximum stream duration (15 min); after it the server closes and the client reconnects, resuming via `Last-Event-ID` |
| `WS_TICKET_TTL_SECONDS` | `30` | No | WebSocket live-progress ticket TTL in seconds. Browsers cannot set custom WebSocket headers, so the WS fallback authenticates with a single-use, short-lived ticket from `POST /scans/{id}/ws-ticket`. |
| `DISCOVERY_PROVIDERS` | `crt_sh` | No | Comma-separated list of enabled discovery provider names (e.g. `crt_sh`). Providers not listed here never run. |
| `MAX_SUBDOMAINS_PER_SOURCE_PER_SCAN` | `500` | No | Max subdomains returned per source per scan (prevents DB flooding); truncated sources set `truncated=true` on the scan record and API response. |
| `CRT_SH_RATE_LIMIT_PER_MIN` | `60` | No | crt.sh global Redis token-bucket rate limit (tokens per minute, shared by all workers). Fail closed if Redis is unavailable. |
| `CRT_SH_CACHE_TTL_SECONDS` | `3600` | No | Per-domain cache TTL for crt.sh CT-log responses (seconds). |
| `CRT_SH_TIMEOUT_SECONDS` | `15.0` | No | crt.sh connect/read timeout (seconds). |
| `CRT_SH_MAX_RETRIES` | `3` | No | crt.sh max retries on transient failure (502/503/504 / network), with exponential backoff. |
| `EMAIL_SECURITY_ENABLED` | `true` | No | Enable the passive email-security scanner module (SPF/DKIM/DMARC/MTA-STS/BIMI DNS lookups). |
| `EMAIL_SECURITY_TIMEOUT_SECONDS` | `5.0` | No | DNS query timeout per record type for email-security lookups (seconds). |
| `EMAIL_SECURITY_MAX_QUERIES` | `12` | No | Max DNS queries per domain for email-security lookups (bounds selector probing). |
| `SUBDOMAIN_TAKEOVER_ENABLED` | `true` | No | Enable the passive/active subdomain takeover scanner module (CNAME → claimable provider detection). |
| `SUBDOMAIN_TAKEOVER_TIMEOUT_SECONDS` | `10.0` | No | DNS/HTTP query timeout per lookup for takeover scanning (seconds). |
| `SUBDOMAIN_TAKEOVER_MAX_CONCURRENCY` | `10` | No | Max concurrent takeover lookups per scan. |
| `SUBDOMAIN_TAKEOVER_MAX_HOSTS_PER_SCAN` | `100` | No | Max subdomains checked for takeover per scan; exceeded hosts are truncated. |
| `SUBDOMAIN_TAKEOVER_MAX_REDIRECTS` | `3` | No | Max HTTP redirects followed during takeover confirmation (each re-validated via SSRF pin). |
| `SUBDOMAIN_TAKEOVER_MAX_BODY_BYTES` | `65536` | No | Max response body bytes read during takeover confirmation. |
| `REQUIRE_DOMAIN_VERIFICATION` | `True` | No | Block scans of unverified domains (local-dev escape hatch only) |
| `VERIFICATION_EXPIRY_DAYS` | `90` | No | Days a verification stays valid |
| `VERIFICATION_GRACE_DAYS` | `14` | No | Grace for migration-grandfathered domains |
| `LOG_LEVEL` | `INFO` | No | Python logging level |
| `LOG_FORMAT` | `text` | No | …or `json` for structured ingestion |
| `HTTP_PORT` / `HTTPS_PORT` | `80` / `443` | No | Host ports published by nginx only (in-container it listens 8080/8443, non-root) |

Frontend: set `VITE_API_BASE` (e.g. `https://api.example.com/api/v1`) to point at a remote API instead of the local Vite proxy.

### Scan scopes

| Scope | Registry phases | Description |
|-------|----------------|-------------|
| `passive` | `discovery`, `email_security` | crt.sh CT logs + passive email-security DNS lookups (SPF/DKIM/DMARC/MTA-STS/BIMI). Zero packets to target ports/services. |
| `active` | `discovery`, `email_security`, `port`, `ssl`, `header` | Passive + port scanning, TLS inspection, HTTP header checks. All active probing requires a verified domain + SSRF-pinned IP. |
| `full` | `discovery`, `email_security`, `port`, `ssl`, `header`, `fingerprint` | Active + passive tech fingerprinting (headers/TLS/HTML mapped to CVE enrichment). CVE enrichment (OSV.dev) enabled. |

### Security model in one paragraph

Multi-tenancy enforced in the application layer (every query scoped by
`organization_id`, characterised by the tenant-matrix suite); auth is
HS256-bearer JWT with hashed refresh/recovery/API-key secrets; Fernet
encryption at rest for alert integrations; TOTP 2FA + recovery; login lockout
and rate limiting on separate layers; Postgres RLS evaluated and **deferred**
(`docs/rls-design.md`). Container posture: non-root UID 10001, read-only
rootfs, `cap_drop: [ALL]`, no-new-privileges, read/write limited to `/tmp`
(tmpfs) and the `kevdata` volume. **Admin step-up re-authentication:** a
fresh password (+ TOTP/recovery when 2FA is on) via `POST /auth/step-up`
plants a server-side Redis marker (`stepup:{user}:{jti}`, TTL 300 s) that
gates sensitive org-admin writes (`403 step_up_required` otherwise; events
`auth.stepup_granted` / `auth.stepup_used` are audited). The frontend
`StepUpDialog` opens on the first `step_up_required` and retries the request;
the marker rides a token's `jti`, so if the access token is refreshed between
verification and the retried call the dialog simply re-verifies again
(bounded by `STEPUP_MAX_RETRIES` in the api client) — the token is never
silently re-bound. **Live scan progress (SSE):** the worker publishes
lifecycle transitions to the Redis Stream `scan:{id}:events` (a
failure-safe publisher — a broken Redis can never fail a scan) and the
browser follows `GET /api/v1/scans/{id}/events` (`text/event-stream`, same
permission and org scoping as reading the scan, Authorization header only —
a token in the query string is always ignored). Opening a stream counts as
exactly ONE request against the global rate limiter; the `: heartbeat`
comments are bytes of that same response and never rate-limit again. Reads
wait 250 ms per XREAD block (1/60 of the heartbeat window), so a client
disconnect is noticed within seconds and frees its cap slot immediately.
Per-user concurrent streams are capped (`SCAN_STREAM_MAX_PER_USER`, 429
`stream_cap_reached`, slots released in a `finally` — including on client
disconnect — and every slot carries its own expiry score of open-time plus
max duration plus a small margin, with stale slots pruned on every open, so
a killed API process cannot leak the cap permanently), and a stream
terminates after
`SCAN_STREAM_MAX_DURATION_SECONDS` (default 15 min; clients reconnect and
resume from `Last-Event-ID` without duplicates). An already-open stream
outlives token expiry up to that max duration — acceptable because the
connection was authorized at open and only replays data authorized for the
calling org (no new resource, no credential in the URL), while every
reconnect — including the duration rollover — re-authenticates with a live
token, so exposure is bounded and identical to any open HTTP response body.
Events carry only data
`GET /scans/{id}` already exposes — status, phase name, integer counts,
short static codes and timestamps — with no error text, banners or other-org
data. Details and the accepted-risk list live in
[`docs/threat-model.md`](docs/threat-model.md); report vulnerabilities via
the guidelines in [`SECURITY.md`](SECURITY.md) (never a public issue).
Licensed under [MIT](LICENSE).

## API surface — `/api/v1`

Full endpoint listing: [`docs/API.md`](docs/API.md) (generated from OpenAPI —
regenerate with `make openapi`).

Quick flavour:

| Area | Typical call |
|------|--------------|
| **auth** | `POST /auth/register`, `/auth/login`, `/auth/refresh`, `/auth/me`, 2FA setup + verify + restart |
| **assets** | `GET /assets`, `/assets/{id}`, `/assets/{id}/graph` |
| **scans** | `POST /scans`, `/scans/verify-ownership`, `/scans/verify-ownership/check` |
| **findings** | `GET /findings`, `/findings/{id}` |
| **scan-policies** | `POST /scan-policies`, `PATCH /scan-policies/{id}`, `/scan-policies/{id}/run-now` |
| **organizations** | invitations, api-keys (create/list/revoke), `GET /organizations/me` |
| **alerting** | integrations CRUD + test send; digest config + email scheduling |
| **reports** | 5 CSV exports + executive-summary PDF + per-finding PDF |
| **dashboard** | `GET /dashboard` aggregate counts |

Error envelope on every non-2xx: `{"error": {"code", "message", "details"}}`.

### Roles & permissions

| Role | Permissions |
|------|------------|
| **viewer** | `asset:read` `finding:read` `scan:read` |
| **analyst** | viewer + `scan:create` `policy:manage` `report:export` |
| **admin** | all 10 permissions (analyst + `asset:write` `alert:manage` `org:manage` `audit:read`) |

API-key scopes (`read` / `write` / `admin`) narrow the owning user's role — never expand it:

```text
effective_permissions = role_permissions ∩ scope_grants
```

### Audit log

`GET /api/v1/audit-logs` (org-managers only) serves this organization's audit
trail with filters (action / actor / since / until / ip), pagination capped at
100 rows/page, and server-side scrubbing of secret-named `details` keys
(`password`, `token`, `webhook`, `url`, … — case-insensitive, at every
nesting level). Note on the IP filter: the `audit_logs.ip_address` column was
introduced by migration `20261020_0001-e5f6a7b8c9d1` — rows written
**before** that migration have no recorded source IP, so the `ip` filter and
the IP column simply come back empty for them.

## Monitoring

Prometheus metrics are exposed at `GET /metrics` (deny by default: a request
needs `Authorization: Bearer $METRICS_BEARER_TOKEN` or a peer inside
`METRICS_ALLOWED_CIDRS`, default `127.0.0.1/32`; the public nginx returns
404 for the path). Point your scraper at the backend with the bearer token:

```yaml
scrape_configs:
  - job_name: sentinelasm
    bearer_token: "<METRICS_BEARER_TOKEN from .env>"
    static_configs:
      - targets: ["backend:8000"]
```

Instrumented automatically via `PrometheusMiddleware`:
- Per-route request count and latency histograms.
- HTTP status code distribution.
- Celery task success/failure/retry counters.

Container health: `backend`, `worker`, `frontend`, `postgres`, `redis`, and
`nginx` all have compose healthchecks. The `beat` scheduler intentionally has
none — there is no reliable in-container signal for it (beat answers no
inspect pings and the slim image ships no `ps`); it is supervised by the
`unless-stopped` restart policy, and a stalled beat is visible as missing
periodic runs plus its container logs. Worker healthcheck behavior is
unchanged.

## Testing

`make check` — must be green before every push (ruff, mypy, pytest on a
fresh `scratch_check` DB created and dropped automatically, tsc, eslint,
prettier, vitest, vite build):

```bash
make check   # needs local Postgres + Redis; PG_SU_USER/PG_SU_PASSWORD override the psql admin creds if they differ
```

Runs all protected matrices through `tests/` in the backend venv (586
characterization tests, no xfail) and 28 vitest frontend tests including
MFA step flow and 2FA recovery display.

> Test counts drift with every sprint; don't quote them as a contract —
> quote `make check` exiting 0.

### Secrets at rest and key rotation

Alert credentials (`secret`, `jira_api_token`, `webhook_url`) are Fernet-encrypted
in the database. **Back up `SECRETS_ENCRYPTION_KEY` in a password manager —
losing it makes stored secrets unrecoverable** (sends fail closed with a
"check SECRETS_ENCRYPTION_KEY" error until a working key is restored).

To rotate: prepend the new key (`NEW,OLD`), run
`scripts/encrypt_secrets.py --rotate` (use `--dry-run` first to preview
counts), verify, then drop the old key. Back up the database before any
rotation or downgrade. See `docs/OPERATIONS.md` for the full runbook
(backup/restore, unlock/reset, upgrade, tag/release).

## Deployment

A `docker-compose.yml` is provided (PostgreSQL 16, Redis 7, FastAPI, Celery worker, Vite SPA, Nginx) hardened for a single-host deployment: app containers run as a fixed non-root user on a read-only rootfs with all capabilities dropped, only nginx publishes host ports (in-container it listens on 8080/8443), Redis requires a generated password, and every image/action is digest- or SHA-pinned. Security posture lives in [`docs/threat-model.md`](docs/threat-model.md).

Publishing is release-tag-only: `docker-publish` builds/pushes ghcr images and
CycloneDX SBOMs **only** for `v*` tags. Tagging ritual + `make release-check`
are in `docs/OPERATIONS.md`.

For a deeper production path (managed PG/Redis, external LB): set
`ENVIRONMENT=production`, strong `JWT_SECRET`, `DEBUG=False`, real SMTP, and
TLS at the edge — see `docs/OPERATIONS.md` "Upgrading / rolling forward".

## Roadmap

- [x] Docker Compose — hardened stack with health checks, compose contract tests
- [x] Nginx unprivileged proxy + SPA serving (read-only rootfs, digest-pinned images, TLS-ready block)
- [x] Frontend code-splitting — vite emits per-route chunks (Dashboard d3 graph is the largest lazy chunk)
- [x] 2FA (TOTP + recovery), login lockout, admin unlock, `/metrics` access gate
- [x] uv hashed lockfile + frontend `package-lock.json`; `make lock/audit/check/release-check`
- [x] Weekly audit workflow; Trivy scans; SHA-pinned Actions; keep-a-changelog release ritual
- [ ] WebSocket live scan progress (polling today)
- [ ] Postgres RLS (deferred by design — see `docs/rls-design.md`)
- [ ] SSO / SCIM integration
- [ ] Real screenshots (staged through `scripts/seed_demo.py`)

## License

Released under the [MIT License](LICENSE).
