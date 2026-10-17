# ── Stage 1: builder ──────────────────────────────────────────────────────────
# Base digests pinned via the Docker Hub registry v2 API (multi-arch manifest
# list digest for the tag, HEAD /v2/library/python/manifests/3.13-slim with a
# Bearer token from auth.docker.io). Re-verify with:
#   curl -sH "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
#     -H "Authorization: Bearer $TOKEN" -I .../manifests/3.13-slim | grep -i docker-content-digest
# python:3.13-slim (tag), sha256 of the manifest list at pin time.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Build toolchain lives ONLY in this stage. psycopg2-binary / psycopg[binary] /
# bcrypt / cryptography ship manylinux wheels, but keeping the toolchain here
# means a missing wheel still builds instead of failing.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
  && rm -rf /var/lib/apt/lists/*

# uv itself pinned by tag AND ghcr digest (same registry-API method, ghcr.io
# token endpoint: /token?service=ghcr.io&scope=repository:astral-sh/uv:pull).
COPY --from=ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 /uv /bin/uv

COPY pyproject.toml uv.lock ./
# Hash-enforced install: --frozen fails if pyproject.toml and uv.lock
# disagree. Runtime deps only (--no-dev keeps pytest/ruff/mypy out).
RUN /bin/uv sync --frozen --no-dev --no-install-project

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
# Same digest as the builder: the venv contains symlinks to /usr/local/bin
# python that must resolve identically here.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Fixed UID/GID 10001, non-login shell. `docker compose exec backend sh`
# still works: exec bypasses the account shell (/usr/sbin/nologin only
# blocks `su`/login paths).
RUN groupadd --gid 10001 sentinel \
  && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sentinel

COPY --from=builder /app/.venv /app/.venv
COPY . .

# The runtime image installs nothing: no apt packages, no package manager
# invocations. Writable paths at runtime are mounts, not disk:
#   /tmp       — tmpfs (temp files, celery remote-control replies)
#   /kev-cache — named volume via KEV_CACHE_DIR (CISA KEV cache)
USER 10001:10001

EXPOSE 8000

# Healthcheck via the stdlib (the runtime image ships no HTTP CLI tools).
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=8)"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
