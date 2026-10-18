# SentinelASM developer entrypoints (Phase 0, task 0.3).
# Prereqs: python3.13 + node20 for local dev, or Docker for `make up`.
# Backend venv lives at backend/venv (see README quickstart); lint also needs
# `pip install ruff mypy`, frontend needs `npm install` under frontend/.

.PHONY: setup migrate dev test lint up down secrets-scan check lock audit openapi release-check

# Local Postgres superuser credentials (only used by `check` to
# create/drop its scratch database; override with `make check
# PG_SU_USER=... PG_SU_PASSWORD=...` if yours differ).
PG_SU_USER ?= postgres
PG_SU_PASSWORD ?= postgres
# Fresh scratch database for `make check`'s pytest run (created and dropped
# every run; never a development or production database).
CHECK_DB_URL = postgresql://sentinel:sentinelpass@localhost:5432/scratch_check

setup: ## first-time env bootstrap (idempotent, never overwrites .env)
	bash scripts/bootstrap.sh

migrate: ## apply database migrations (needs backend venv + running Postgres)
	cd backend && venv/bin/alembic upgrade head

dev: ## run the API locally with reload on http://localhost:8000
	cd backend && venv/bin/uvicorn main:app --reload --port 8000

test: ## backend pytest + frontend vitest + frontend production build
	cd backend && venv/bin/python -m pytest tests/ -q -p no:warnings
	cd frontend && npm test
	cd frontend && npm run build

lint: ## ruff + mypy (backend) and eslint + prettier check (frontend)
	cd backend && ruff check .
	cd backend && venv/bin/mypy . --ignore-missing-imports
	cd frontend && npx eslint src --ext .ts,.tsx
	cd frontend && npx prettier --check src

up: setup ## full stack via compose on http://localhost (needs Docker)
	docker compose up --build

down: ## stop the compose stack
	docker compose down

lock: ## regenerate backend/uv.lock from backend/pyproject.toml
	cd backend && uv lock

audit: ## pip-audit over the locked backend set + npm audit (frontend prod)
	cd backend && uv export --frozen --no-dev --output-file /tmp/sentinelasm-requirements.audit.txt && uvx pip-audit -r /tmp/sentinelasm-requirements.audit.txt; rm -f /tmp/sentinelasm-requirements.audit.txt
	cd frontend && npm audit --omit=dev --audit-level=high

release-check: ## full pre-tag gate: make check + make audit + lockfile currency (run before cutting a v* tag; see docs/OPERATIONS.md)
	$(MAKE) check
	$(MAKE) audit
	cd backend && uv lock --check
	cd frontend && npm ci --dry-run >/dev/null

check: ## CI gate mirror, in order (run before every push): ruff, mypy, pytest on a fresh scratch DB, tsc, eslint, prettier, vitest, vite build
	cd backend && ruff check .
	cd backend && venv/bin/mypy . --ignore-missing-imports
	DATABASE_URL=$(CHECK_DB_URL) bash scripts/db_guard.sh
	PGPASSWORD=$(PG_SU_PASSWORD) psql -h localhost -U $(PG_SU_USER) -c "DROP DATABASE IF EXISTS scratch_check;" -c "CREATE DATABASE scratch_check;"
	PGPASSWORD=$(PG_SU_PASSWORD) psql -h localhost -U $(PG_SU_USER) -d scratch_check -c "GRANT ALL ON SCHEMA public TO sentinel;"
	cd backend && DATABASE_URL=$(CHECK_DB_URL) REDIS_URL=redis://localhost:6379/15 JWT_SECRET=test-secret-key-for-ci SECRETS_ENCRYPTION_KEY=65oXmy07q8CjkFHoNljDp294eAbZDmRN4bJd1Ax3lo8= venv/bin/python -m pytest tests/ -q -p no:warnings
	PGPASSWORD=$(PG_SU_PASSWORD) psql -h localhost -U $(PG_SU_USER) -c "DROP DATABASE IF EXISTS scratch_check;"
	cd frontend && npx tsc --noEmit
	cd frontend && npx eslint src --ext .ts,.tsx
	cd frontend && npx prettier --check src
	cd frontend && npm test
	cd frontend && npm run build

openapi: ## regenerate docs/openapi.json + docs/API.md from the app (schema-only; no DB, no network)
	cd backend && KEY=$$(venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") JWT_SECRET=openapi-export-dummy-value SECRETS_ENCRYPTION_KEY=$$KEY REDIS_URL=redis://localhost:6379/15 venv/bin/python scripts/export_openapi.py

secrets-scan: ## gitleaks secret scan (blocking; needs a gitleaks binary or Docker)
	if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --source . --config .gitleaks.toml; \
	else \
		docker run --rm -v "$$(pwd):/repo" ghcr.io/gitleaks/gitleaks:v8.29.1 detect --source /repo --config /repo/.gitleaks.toml; \
	fi
