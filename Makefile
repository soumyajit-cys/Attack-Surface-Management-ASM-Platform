# SentinelASM developer entrypoints (Phase 0, task 0.3).
# Prereqs: python3.13 + node20 for local dev, or Docker for `make up`.
# Backend venv lives at backend/venv (see README quickstart); lint also needs
# `pip install ruff mypy`, frontend needs `npm install` under frontend/.

.PHONY: setup migrate dev test lint up down secrets-scan

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

secrets-scan: ## gitleaks secret scan (blocking; needs a gitleaks binary or Docker)
	if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --source . --config .gitleaks.toml; \
	else \
		docker run --rm -v "$$(pwd):/repo" ghcr.io/gitleaks/gitleaks:v8.29.1 detect --source /repo --config /repo/.gitleaks.toml; \
	fi
