"""Container and compose hardening contract (task 1.6 batch 3).

Locks in: multi-stage Dockerfiles with digest-pinned bases, non-root
runtime stages, .dockerignore coverage, unprivileged nginx ports, and the
compose security posture (read-only rootfs, tmpfs /tmp, cap_drop ALL,
no-new-privileges, resource limits, nginx-only port publishing, Redis
auth, KEV cache volume). No Docker daemon, no DB, no network.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = ROOT / "docker-compose.yml"
NGINX_CONF = ROOT / "nginx" / "nginx.conf"
FRONTEND_NGINX_CONF = ROOT / "frontend" / "nginx.conf"
BACKEND_DOCKERFILE = ROOT / "backend" / "Dockerfile"
FRONTEND_DOCKERFILE = ROOT / "frontend" / "Dockerfile"

# Services that run our code and must carry the full hardening posture.
APP_SERVICES = ["backend", "worker", "beat", "frontend", "nginx"]


@pytest.fixture(scope="module")
def compose():
    with open(COMPOSE_FILE) as f:
        return yaml.safe_load(f)


# ── Dockerfiles ──────────────────────────────────────────────────────────────


def test_dockerfiles_are_multi_stage():
    """Build tools must not survive into the runtime image."""
    for path in [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE]:
        text = path.read_text()
        assert text.count("FROM ") >= 2, f"{path} is not multi-stage"


def test_dockerfiles_pin_bases_by_digest():
    """Every FROM line pins tag AND digest (supply-chain immutability)."""
    for path in [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE]:
        for line in path.read_text().splitlines():
            if line.startswith("FROM "):
                assert "@sha256:" in line, f"{path}: unpinned FROM: {line}"


def test_dockerfiles_run_as_non_root():
    """Runtime stage (last FROM onward) declares a non-root USER (DS-0002)."""
    for path in [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE]:
        text = path.read_text()
        runtime = text[text.rfind("FROM ") :]
        assert "USER " in runtime, f"{path} runtime stage has no USER directive"


def test_backend_runtime_has_no_build_tools():
    """build-essential/libpq-dev/curl must not appear in the runtime stage."""
    text = BACKEND_DOCKERFILE.read_text()
    runtime = text[text.rfind("FROM ") :]
    for tool in ["build-essential", "libpq-dev", "curl", "apt-get"]:
        assert tool not in runtime, f"backend runtime stage still installs {tool}"


def test_dockerignore_files_exist_and_cover_basics():
    for path in [ROOT / "backend" / ".dockerignore", ROOT / "frontend" / ".dockerignore"]:
        assert path.exists(), f"{path} is missing"
        text = path.read_text()
        for entry in [".git", "node_modules", "venv", "tests", ".env", "dist", "__pycache__"]:
            assert entry in text, f"{path} does not exclude {entry}"


# ── nginx ────────────────────────────────────────────────────────────────────


def test_nginx_listens_on_unprivileged_ports():
    """Frontend server and reverse proxy both avoid ports 80/443 in-container."""
    assert "listen 8080" in FRONTEND_NGINX_CONF.read_text()
    proxy = NGINX_CONF.read_text()
    assert "listen 8080" in proxy
    # TLS-ready block stays commented but moves to the unprivileged port.
    assert "8443 ssl" in proxy


# ── compose ──────────────────────────────────────────────────────────────────


def test_compose_images_pinned_by_digest():
    for name, svc in compose["services"].items():
        image = svc.get("image")
        if image:
            assert "@sha256:" in image, f"{name} image not digest-pinned: {image}"


def test_app_services_read_only_rootfs():
    for name in APP_SERVICES:
        assert compose["services"][name].get("read_only") is True, (
            f"{name} missing read_only: true"
        )


def test_app_services_tmpfs_tmp():
    for name in APP_SERVICES:
        tmpfs = compose["services"][name].get("tmpfs", [])
        assert any(str(t).split(":")[0] == "/tmp" for t in tmpfs), (
            f"{name} missing /tmp tmpfs"
        )


def test_app_services_drop_all_capabilities():
    for name in APP_SERVICES:
        assert compose["services"][name].get("cap_drop") == ["ALL"], (
            f"{name} does not cap_drop ALL"
        )


def test_app_services_no_new_privileges():
    for name in APP_SERVICES:
        opts = compose["services"][name].get("security_opt", [])
        assert "no-new-privileges:true" in opts, f"{name} missing no-new-privileges"


def test_app_services_resource_limits():
    for name in APP_SERVICES:
        svc = compose["services"][name]
        for key in ["mem_limit", "cpus", "pids_limit"]:
            assert key in svc, f"{name} missing {key}"


def test_only_nginx_publishes_ports():
    for name, svc in compose["services"].items():
        if name == "nginx":
            assert svc.get("ports"), "nginx must publish host ports"
        else:
            assert not svc.get("ports"), f"{name} must not publish host ports"


def test_redis_requires_password():
    redis_svc = compose["services"]["redis"]
    cmd = " ".join(map(str, redis_svc.get("command", [])))
    assert "requirepass" in cmd, "redis must require a password"
    hc = " ".join(map(str, redis_svc["healthcheck"]["test"]))
    assert "REDISCLI_AUTH" in hc, "redis healthcheck must authenticate"


def test_backend_services_have_kev_cache_volume():
    """KEV cache dir comes from a named volume via KEV_CACHE_DIR."""
    for name in ["backend", "worker", "beat"]:
        svc = compose["services"][name]
        env = svc.get("environment", {})
        assert env.get("KEV_CACHE_DIR") == "/kev-cache", f"{name} missing KEV_CACHE_DIR"
        mounts = svc.get("volumes", [])
        assert any("kev-cache" in str(m) or "kevdata" in str(m) for m in mounts), (
            f"{name} missing KEV cache volume"
        )
