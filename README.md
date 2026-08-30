# Attack-Surface-Management-ASM-Platform (SentinelASM)

SentinelASM is a professional Attack Surface Management platform. It discovers internet-facing assets for your organization, enumerates subdomains and open ports, synthesizes security findings, computes risk scores, and exposes everything through a clean REST API, a React dashboard, CSV/PDF reports, email digests, and integration hooks.

Built with **FastAPI, SQLAlchemy, PostgreSQL, Redis, Celery**, and a **React 18 + TypeScript + Vite + Tailwind** frontend.

## Features

- **Asset discovery pipeline** — domain resolution (SSRF-pinned), DNS/subdomain enumeration, port scanning, SSL/TLS inspection, driven by a Celery worker with retries and a dead-letter queue.
- **Multi-tenant isolation** — every query is scoped by `organization_id`; assets, findings, scans, policies, keys and integrations can never leak across tenants.
- **Fine-grained permissions** — JWT users get permissions derived from their role; API keys carry coarse `read`/`write`/`admin` scopes that are intersected with the owning user's role grants.
- **Domain ownership verification** — `verify-ownership` flow (DNS TXT method) gatekeeps scanning external targets.
- **Risk engine** — per-asset risk scoring and exposure classification driven by synthesized findings.
- **Alerting & digests** — alert integrations (create/test/delete) plus scheduled email digests via Celery Beat.
- **Reporting** — CSV exports (findings/assets/scans/domains/all) and PDF reports (executive summary, per-finding) via `fpdf2`.
- **Dashboard & asset graph** — live metrics dashboard (Recharts) and a d3-based network map of an asset's domains, subdomains, ports and certificates.
- **Observability** — Prometheus `/metrics` endpoint with per-route middleware.

## Architecture

```
Browser (React + Vite)
        │  /api/v1  (JWT Bearer or X-API-Key)
        ▼
    FastAPI app ──────────▶ PostgreSQL (SQLAlchemy + Alembic)
        │
        ├──▶ Redis  (broker, token blacklist, refresh store, rate-limit store)
        │
        └──▶ Celery worker ── assets discovery pipeline (retries → DLQ)
              └─ Celery Beat ── scan-policy scheduler + email digests
```

- The Vite dev server proxies `/api` to `http://localhost:8000`.
- API responses use a consistent error envelope: `{"error": {"code", "message", "details"}}`.

## Repository layout

```
backend/            FastAPI application, models, services, workers, tests
  api/              HTTP layer (legacy routes + app/api/v1 clean surface)
  app/api/v1/       v1 routes: auth, assets, scans, findings, dashboard, ...
  models/           SQLAlchemy models
  services/         discovery, findings, scoring, alerts
  tasks/            Celery tasks (discovery, scheduler/digest)
  workers/          Celery app wiring
  migrations/       Alembic migrations
  tests/            Pytest suite (currently 156 passing)
frontend/           React 18 + TypeScript + Vite + Tailwind SPA
  src/pages/        Dashboard, Assets, AssetDetail (+d3 graph), Scans, ...
  src/lib/api.ts    Typed axios client for /api/v1
```

## Getting started (local development)

### Prerequisites

- Python 3.11+
- Node.js 18+ (npm)
- PostgreSQL 16 running on `localhost:5432`
- Redis 7 running on `localhost:6379`

### 1. Database

Create the database (using the defaults in `.env.example`):

```sql
CREATE USER sentinel WITH PASSWORD 'sentinelpass';
CREATE DATABASE sentinelasm OWNER sentinel;
```

Apply migrations:

```bash
cd backend
alembic upgrade head
```

### 2. Backend API

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Set JWT_SECRET (required — the app refuses to start without one):
python -c "import secrets; print(secrets.token_hex(32))"

uvicorn main:app --reload --port 8000
```

The API and interactive docs are served at `http://localhost:8000/docs`.

### 3. Celery worker (+ Beat) — required for scanning

```bash
cd backend
source venv/bin/activate
celery -A workers.celery_app:celery worker -l info

# optional scheduler (scan policies + email digests):
celery -A workers.celery_app:celery beat -l info
```

### 4. Frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173  (proxies /api → :8000)
```

To point the frontend at a remote API instead, set `VITE_API_BASE` (e.g. `https://api.example.com/api/v1`) before building.

### Ports

| Service      | Port | Notes                              |
|--------------|------|------------------------------------|
| Frontend     | 5173 | Vite dev server                    |
| API          | 8000 | `/docs` for OpenAPI                |
| PostgreSQL   | 5432 | database `sentinelasm`             |
| Redis        | 6379 | broker / blacklist / rate limits   |

## API surface (`/api/v1`)

| Module | Endpoints |
|--------|-----------|
| **auth** | `register`, `login`, `refresh`, `logout`, `me`, `forgot-password`, `reset-password` |
| **assets** | list (paginated, search/filter), detail (nested domains/subdomains/ports/SSL), `/{id}/graph` |
| **scans** | start scan, list, status, `verify-ownership`, `verify-ownership/check` |
| **findings** | list (paginated, filter), detail (includes `asset_name`) |
| **scan-policies** | CRUD + `/{id}/run-now` (daily/weekly/monthly/custom_cron) |
| **organizations** | `me`, invitations (create/revoke), API keys (create/revoke) |
| **alerting** | integrations (CRUD + test), email digest config (get/create/update/delete) |
| **reports** | CSV: findings, assets, scans, domains, all · PDF: executive summary, finding |
| **dashboard** | aggregate counts and severity distribution |

## Authentication & authorization

- **JWT** bearer tokens (short-lived access + refresh). Set `Authorization: Bearer <token>`.
- **API keys** — send `X-API-Key: sk...`. Keys carry `read`, `write`, or `admin` scopes; an effective permission set equals `role_permissions ∩ scope_grants`, so scopes can only narrow a user's rights.
- **Roles & permissions** are defined in `backend/app/core/permissions.py`.
- **Multi-tenancy** — session/API-key principals carry an `organization_id`; every route filters through it.

## Reports

- CSV exports and PDF reports are gated behind the same permission dependency as the read endpoints.
- PDF generation requires `fpdf2` (bundled in `requirements.txt`); if missing, PDF routes return a clear error message.

## Testing

```bash
cd backend && source venv/bin/activate
python -m pytest tests/ -q -p no:warnings      # 156 passed

cd frontend
npm run build                                   # tsc && vite build
```

## Deployment

A `docker-compose.yml` describing `postgres`, `redis`, `backend`, `worker`, `frontend`, and `nginx` services is present, but container images/nginx config are still work in progress — local development above is the supported path today.