# SentinelASM

> Attack Surface Management platform — discover, analyse, score, and monitor every internet-facing asset your organisation owns.

SentinelASM automates the full ASM lifecycle: domain resolution (SSRF-pinned), subdomain enumeration, port scanning, SSL/TLS inspection, finding synthesis, risk scoring, alerting, and reporting — all behind a clean **/api/v1** REST surface and a **React** dashboard.

---

## Highlights

- **End-to-end discovery pipeline** — Celery-powered workers with retries, dead-letter queues, and Celery Beat scheduling.
- **Multi-tenant by default** — every query is scoped to an organisation; no data can leak across tenants.
- **Fine-grained RBAC** — three roles (viewer / analyst / admin) backed by 10 discrete permissions; API keys narrow scope further.
- **Domain ownership verification** — DNS-TXT challenge before any external scan runs.
- **Real-time dashboard** — severity breakdowns, asset and finding counts, trend data.
- **Asset graph** — d3-powered network map of domains, subdomains, ports, and certificates.
- **Reports** — CSV (5 flavours) and PDF (executive summary + per-finding) via `fpdf2`.
- **Alerting** — integration webhooks + scheduled email digests (Celery Beat).
- **Observability** — Prometheus `/metrics` endpoint with per-route instrumentation.

---

## Architecture

```mermaid
flowchart TD
    BROWSER["React SPA<br/>Vite + TypeScript"]
    PROXY["Vite proxy<br/>/api → :8000"]
    API["FastAPI app<br/>Port 8000"]
    DB[(PostgreSQL 16)]
    REDIS[(Redis 7)]
    WORKER["Celery worker<br/>discovery pipeline"]
    BEAT["Celery Beat<br/>scheduler + digest"]
    PROM["Prometheus<br/>/metrics"]

    BROWSER --> PROXY
    PROXY -->|JWT or X-API-Key| API
    API --> DB
    API --> REDIS
    WORKER --> REDIS
    WORKER --> DB
    BEAT --> REDIS
    API -.-> PROM
```

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, TypeScript 5, Vite 5, Tailwind CSS 3, Recharts 2, d3 7, Axios |
| **Backend** | FastAPI 0.2.0, SQLAlchemy, Alembic, Pydantic v2 |
| **Database** | PostgreSQL 16 |
| **Cache / Broker** | Redis 7 (Celery broker, token blacklist, rate-limit storage) |
| **Task queue** | Celery 5 (retries, DLQ, Beat scheduler) |
| **Auth** | JWT (python-jose), bcrypt, scoped API keys |
| **Observability** | prometheus-client, Structured logging |
| **PDF** | fpdf2 ≥ 2.7 |
| **Infra** | Docker Compose (WIP) |

---

## Repository layout

```
.
├── backend/
│   ├── api/                    # Legacy HTTP routes
│   ├── app/
│   │   ├── api/v1/             # v1 REST surface (auth, assets, scans, …)
│   │   ├── core/               # config, errors, permissions, SSRF pinning
│   │   └── db/                 # session, engine
│   ├── models/                 # SQLAlchemy models
│   ├── services/               # discovery, findings, scoring, alerts
│   ├── tasks/                  # Celery tasks (discovery, scheduler)
│   ├── workers/                # Celery app + DLQ wiring
│   ├── migrations/             # Alembic
│   └── tests/                  # Pytest (156 passing)
├── frontend/
│   └── src/
│       ├── pages/              # Dashboard, Assets, Scans, Findings, …
│       ├── lib/api.ts          # Typed axios client for /api/v1
│       ├── contexts/           # AuthContext
│       ├── components/ui/      # Toaster, modals, layout
│       └── AssetGraph.tsx      # d3 force-directed graph
├── docker-compose.yml          # Compose stack (WIP)
└── README.md
```

---

## Quick start

```bash
# 1 — create the database
psql -U postgres -c "CREATE USER sentinel WITH PASSWORD 'sentinelpass';"
psql -U postgres -c "CREATE DATABASE sentinelasm OWNER sentinel;"

# 2 — backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# generate a real JWT_SECRET and paste it into .env:
python -c "import secrets; print(secrets.token_hex(32))"
alembic upgrade head
uvicorn main:app --reload --port 8000 &

# 3 — celery worker (+ optional beat)
celery -A workers.celery_app:celery worker -l info &
celery -A workers.celery_app:celery beat -l info &

# 4 — frontend
cd ../frontend
npm install
npm run dev          # → http://localhost:5173
```

Open `http://localhost:5173`, register an account, and start a scan on `example.com`.

---

## Configuration

All backend configuration lives in `backend/.env` (copy from `.env.example`).

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `DATABASE_URL` | `postgresql://sentinel:sentinelpass@localhost:5432/sentinelasm` | Yes | SQLAlchemy connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Yes | Celery broker + token blacklist |
| `JWT_SECRET` | — | **Yes** | HS256 signing key; app **refuses to start** without one |
| `JWT_ALGORITHM` | `HS256` | No | |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | No | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | No | Refresh token lifetime |
| `SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` | (empty) | No | Required for password-reset emails and digest delivery |
| `SMTP_FROM` | `sentinelasm@example.com` | No | |
| `FRONTEND_URL` | `http://localhost:5173` | No | Used in password-reset links |
| `APP_NAME` | `SentinelASM` | No | |
| `DEBUG` | `True` | No | |

Frontend: set `VITE_API_BASE` (e.g. `https://api.example.com/api/v1`) to point at a remote API instead of the local Vite proxy.

---

## API surface — `/api/v1`

| Module | Method | Path | Description |
|--------|--------|------|-------------|
| **auth** | POST | `/auth/register` | Create user + organisation |
| | POST | `/auth/login` | Returns `TokenBundle` |
| | POST | `/auth/refresh` | Rotate access token |
| | POST | `/auth/logout` | Blacklist refresh token |
| | POST | `/auth/forgot-password` | Send reset email |
| | POST | `/auth/reset-password` | Consume reset token |
| | GET | `/auth/me` | Current user profile + permissions |
| **assets** | GET | `/assets` | Paginated list (search, criticality filter) |
| | GET | `/assets/{id}` | Detail with nested domains/subdomains/ports/SSL |
| | GET | `/assets/{id}/graph` | d3 nodes + edges payload |
| **scans** | POST | `/scans` | Start a scan (queues `run_discovery`) |
| | GET | `/scans` | Paginated list |
| | GET | `/scans/{id}` | Status + metadata |
| | POST | `/scans/verify-ownership` | Initiate DNS-TXT challenge |
| | GET | `/scans/verify-ownership/check` | Poll challenge status |
| **findings** | GET | `/findings` | Paginated list (severity filter) |
| | GET | `/findings/{id}` | Detail with `asset_name` |
| **scan-policies** | GET | `/scan-policies` | List policies |
| | POST | `/scan-policies` | Create (daily / weekly / monthly / custom_cron) |
| | PATCH | `/scan-policies/{id}` | Update |
| | DELETE | `/scan-policies/{id}` | Delete |
| | POST | `/scan-policies/{id}/run-now` | Trigger immediately |
| **organizations** | GET | `/organizations/me` | Org details |
| | GET | `/organizations/invitations` | Pending invitations |
| | POST | `/organizations/invitations` | Send invite |
| | DELETE | `/organizations/invitations/{id}/revoke` | Revoke |
| | GET | `/organizations/api-keys` | List keys (no secret) |
| | POST | `/organizations/api-keys` | Create (returns `key` once) |
| | DELETE | `/organizations/api-keys/{id}` | Revoke |
| **alerting** | GET | `/alerting/integrations` | List integrations |
| | POST | `/alerting/integrations` | Create (optional `secret`) |
| | DELETE | `/alerting/integrations/{id}` | Delete |
| | POST | `/alerting/integrations/{id}/test` | Send test payload |
| | GET | `/alerting/digest` | Get digest config (404 if none) |
| | POST | `/alerting/digest` | Create |
| | PATCH | `/alerting/digest` | Update |
| | DELETE | `/alerting/digest` | Delete |
| **reports** | POST | `/reports/export/findings/csv` | Findings CSV |
| | POST | `/reports/export/assets/csv` | Assets CSV |
| | POST | `/reports/export/scans/csv` | Scans CSV |
| | POST | `/reports/export/domains/csv` | Domains CSV |
| | POST | `/reports/export/all/csv` | Combined CSV |
| | GET | `/reports/pdf/executive-summary` | Executive PDF (optional `asset_id`, `since`) |
| | GET | `/reports/pdf/finding/{id}` | Per-finding PDF |
| **dashboard** | GET | `/dashboard` | Aggregate counts |

All responses on error use the envelope `{"error": {"code", "message", "details"}}`.

---

## Authentication & authorisation

### JWT

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"…"}'
# → {"access_token":"…","refresh_token":"…","user":{…}}
```

```bash
curl http://localhost:8000/api/v1/dashboard \
  -H "Authorization: Bearer <access_token>"
```

### API keys

```bash
KEY=$(curl -s -X POST http://localhost:8000/api/v1/organizations/api-keys \
  -H "Authorization: Bearer <token>" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci","scopes":"read","expires_days":30}' | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])")

curl http://localhost:8000/api/v1/dashboard -H "X-API-Key: $KEY"
```

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

---

## Reports

| Report | Format | Path | Notes |
|--------|--------|------|-------|
| Findings | CSV POST | `/reports/export/findings/csv` | Accepts optional `asset_id`, `since`, `severity` |
| Assets | CSV POST | `/reports/export/assets/csv` | |
| Scans | CSV POST | `/reports/export/scans/csv` | |
| Domains | CSV POST | `/reports/export/domains/csv` | |
| All | CSV POST | `/reports/export/all/csv` | Combined |
| Executive summary | PDF GET | `/reports/pdf/executive-summary` | Optional `asset_id`, `since` |
| Single finding | PDF GET | `/reports/pdf/finding/{id}` | |

PDF generation requires `fpdf2` on the backend; if missing the endpoint returns a descriptive error instead of crashing.

---

## Monitoring

Prometheus metrics are exposed at `GET /metrics` (path may vary by deployment).

Instrumented automatically via `PrometheusMiddleware`:
- Per-route request count and latency histograms.
- HTTP status code distribution.
- Celery task success/failure/retry counters.

---

## Testing

```bash
# Backend — 156 tests, ~60 s
cd backend && source venv/bin/activate
python -m pytest tests/ -q -p no:warnings

# Frontend — type-check + production build
cd frontend
npm run build        # tsc --noEmit && vite build
```

Test environment variables (used by `tests/`):
- `DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/sentinelasm_test`
- `REDIS_URL=redis://localhost:6379/15`
- `JWT_SECRET=test-secret-please-change`

---

## Deployment

A `docker-compose.yml` is provided (PostgreSQL 16, Redis 7, FastAPI, Celery worker, Vite SPA, Nginx) but container images and nginx config are still work-in-progress.

For production today:

1. Deploy the backend + Celery on a server with access to PostgreSQL and Redis.
2. Build the frontend (`npm run build`) and serve the `dist/` folder via Nginx.
3. Point Nginx `/api` → backend (port 8000).
4. Use a production PostgreSQL and Redis (not the defaults above).
5. Set a strong `JWT_SECRET` and disable `DEBUG`.

---

## Roadmap

- [ ] Docker Compose — working stack with health checks, production config
- [ ] Nginx config for reverse proxying `/api` and serving the SPA
- [ ] Frontend code-splitting (lazy routes) to reduce the 791 kB bundle
- [ ] WebSocket support for live scan progress
- [ ] Role-based invitation flows (admin invites analyst, viewer)
- [ ] Audit-log viewer in the dashboard
- [ ] SCIM / SSO integration

---

## License

Not yet specified. Contact the maintainers before using in production.