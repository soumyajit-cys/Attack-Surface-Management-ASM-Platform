"""Item 1: production Docker Compose contract tests.

Validates that docker-compose.yml exposes the full production stack
(backend, frontend, postgres, redis, worker, beat, nginx) with
healthchecks + restart policies, and that the supporting files
(Dockerfiles, nginx TLS-ready config, .env.example) exist.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
NGINX_CONF = ROOT / "nginx" / "nginx.conf"
BACKEND_DOCKERFILE = ROOT / "backend" / "Dockerfile"
FRONTEND_DOCKERFILE = ROOT / "frontend" / "Dockerfile"

REQUIRED_SERVICES = {"backend", "frontend", "postgres", "redis", "worker", "beat", "nginx"}


@pytest.fixture(scope="module")
def compose():
    assert COMPOSE_FILE.exists(), "docker-compose.yml is missing"
    with open(COMPOSE_FILE) as f:
        data = yaml.safe_load(f)
    assert "services" in data
    return data


def test_all_required_services_present(compose):
    assert REQUIRED_SERVICES.issubset(set(compose["services"]))


def test_postgres_redis_versions(compose):
    assert "postgres:16" in compose["services"]["postgres"]["image"]
    assert "redis:7" in compose["services"]["redis"]["image"]


def test_every_service_has_restart_policy(compose):
    for name, svc in compose["services"].items():
        assert svc.get("restart") in {"unless-stopped", "always"}, f"{name} missing restart policy"


def test_core_services_have_healthchecks(compose):
    for name in ["postgres", "redis", "backend", "frontend", "nginx"]:
        svc = compose["services"][name]
        assert "healthcheck" in svc, f"{name} missing healthcheck"
        assert "test" in svc["healthcheck"], f"{name} healthcheck missing test"


def test_worker_and_beat_run_celery(compose):
    worker_cmd = " ".join(map(str, compose["services"]["worker"].get("command", [])))
    beat_cmd = " ".join(map(str, compose["services"]["beat"].get("command", [])))
    assert "celery" in worker_cmd and "worker" in worker_cmd
    assert "celery" in beat_cmd and "beat" in beat_cmd


def test_backend_runs_migrations_then_uvicorn(compose):
    cmd = " ".join(map(str, compose["services"]["backend"].get("command", [])))
    assert "alembic upgrade head" in cmd
    assert "uvicorn" in cmd


def test_nginx_proxies_api_and_serves_spa():
    assert NGINX_CONF.exists(), "nginx/nginx.conf is missing"
    text = NGINX_CONF.read_text()
    assert "location /api/" in text
    assert "proxy_pass http://backend" in text
    assert "proxy_pass http://frontend" in text


def test_nginx_tls_ready():
    text = NGINX_CONF.read_text()
    assert "443 ssl" in text  # commented TLS block counts as TLS-ready
    assert "ssl_certificate" in text


def test_env_example_documents_required_vars():
    assert ENV_EXAMPLE.exists(), ".env.example is missing at repo root"
    text = ENV_EXAMPLE.read_text()
    for var in ["POSTGRES_PASSWORD", "DATABASE_URL", "REDIS_URL", "JWT_SECRET", "FRONTEND_URL"]:
        assert var in text, f".env.example missing {var}"


def test_dockerfiles_exist_with_healthchecks():
    for path in [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE]:
        assert path.exists(), f"{path} is missing"
        assert "HEALTHCHECK" in path.read_text(), f"{path} missing HEALTHCHECK"


def test_frontend_dockerfile_builds_and_serves():
    text = FRONTEND_DOCKERFILE.read_text()
    assert "npm run build" in text
    assert "nginx" in text.lower()
