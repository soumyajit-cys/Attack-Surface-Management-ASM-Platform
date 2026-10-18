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
    API -.->|/metrics gated| PROM["Prometheus scratcher (deny-by-default)"]
```

## Feature status

| Capability | Status | Notes |
|------------|--------|-------|
| Domain ownership verification (DNS-TXT) | ✅ works | Block scans until verified; expiry + recheck scheduling |
| Subdomain / port / DNS / SSL / WHOIS enumeration | ✅ works | Celery pipeline w/ retries + DLQ; per-target enrichment timeouts |
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
| API keys (scoped, hashed, expiry) | ✅ works | Intersect-only, never expand role |
| Audit log of privileged actions | ✅ works | Written on sensitive endpoints |
| Real-time scan progress (WebSocket) | 🔜 planned | Polling today (`GET /scans/{id}`) |
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
cd backend && venv/bin/python ../scripts/seed_demo.py   # made in item 5; refuses non-demo_/scratch_ DBs
```

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
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `120` | No | Global API limiter budget |
| `RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE` | `10` | No | Tighter cap on login/register/reset endpoints |
| `RATE_LIMIT_SCAN_REQUESTS_PER_MINUTE` | `5` | No | Cap on scan-trigger endpoint (dense abuse vector) |
| `OSV_API_URL` / `OSV_TIMEOUT_SECONDS` / `OSV_ENABLED` | `https://api.osv.dev/v1/query` / `10.0` / `True` | No | CVE enrichment feed |
| `KEV_CACHE_DIR` | (empty → `/tmp`) | No | CISA KEV cache dir; compose sets `/kev-cache` named volume (rootfs is read-only) |
| `WEBHOOK_ALLOWED_PORTS` | `443,8443` | No | Ports Slack/Discord/Jira deliveries may target (save + send enforced) |
| `TRUSTED_PROXIES` | (empty) | No | CIDRs allowed to set X-Forwarded-For; compose sets `172.28.0.0/16` (fixed `sentinelnet` subnet for bundled nginx) |
| `METRICS_BEARER_TOKEN` | (empty) | No | Bearer token admitted to `/metrics` (generated by bootstrap.sh) |
| `METRICS_ALLOWED_CIDRS` | `127.0.0.1/32` | No | Peer CIDRs admitted to `/metrics` without a token |
| `LOGIN_MAX_ATTEMPTS` | `5` | No | Failed logins before lockout engages |
| `LOGIN_ATTEMPT_WINDOW_SECONDS` | `300` | No | Sliding window for counting failures |
| `LOGIN_LOCKOUT_BASE_SECONDS` | `60` | No | First lock duration; doubles per engagement |
| `LOGIN_LOCKOUT_MAX_SECONDS` | `900` | No | Cap on lock duration |
| `REQUIRE_DOMAIN_VERIFICATION` | `True` | No | Block scans of unverified domains (local-dev escape hatch only) |
| `VERIFICATION_EXPIRY_DAYS` | `90` | No | Days a verification stays valid |
| `VERIFICATION_GRACE_DAYS` | `14` | No | Grace for migration-grandfathered domains |
| `LOG_LEVEL` | `INFO` | No | Python logging level |
| `LOG_FORMAT` | `text` | No | …or `json` for structured ingestion |
| `HTTP_PORT` / `HTTPS_PORT` | `80` / `443` | No | Host ports published by nginx only (in-container it listens 8080/8443, non-root) |

Frontend: set `VITE_API_BASE` (e.g. `https://api.example.com/api/v1`) to point at a remote API instead of the local Vite proxy.

### Security model in one paragraph

Multi-tenancy enforced in the application layer (every query scoped by
`organization_id`, characterised by the tenant-matrix suite); auth is
HS256-bearer JWT with hashed refresh/recovery/API-key secrets; Fernet
encryption at rest for alert integrations; TOTP 2FA + recovery; login lockout
and rate limiting on separate layers; Postgres RLS evaluated and **deferred**
(`docs/rls-design.md`). Container posture: non-root UID 10001, read-only
rootfs, `cap_drop: [ALL]`, no-new-privileges, read/write limited to `/tmp`
(tmpfs) and the `kevdata` volume. Details and the accepted-risk list live in
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
