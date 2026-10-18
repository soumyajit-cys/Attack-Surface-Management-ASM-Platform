"""Export docs/openapi.json from the running app and render docs/API.md.

`make openapi` runs this with the backend venv: no DB, no network, no
services — it only builds the schema and writes two files. Rerun it any
time routes change; tests/v3/test_openapi_docs.py fails when committed
copies drift from the schema the app actually serves.
"""

from __future__ import annotations

import json
from pathlib import Path

# backend/scripts/ lives inside the backend tree so the renderer is
# importable by the drift tests; docs/ itself is at the repository root.
ROOT = Path(__file__).resolve().parents[2]


def render_api_md(schema: dict) -> str:
    lines: list[str] = [
        "# SentinelASM API",
        "",
        "Generated from the OpenAPI schema of the running app"
        " (`make openapi` regenerates this file together with"
        " `docs/openapi.json`; the drift tests in"
        " `backend/tests/v3/test_openapi_docs.py` fail when either is stale).",
        "",
        "Base URL: `/api/v1`. Every non-2xx uses the error envelope",
        '`{"error": {"code", "message", "details"}}`. Auth: `Authorization: Bearer <access_token>`',
        "or `X-API-Key: <key>`; `/auth/*` and `/health` need neither.",
        "",
        "| Path | Method | Summary | Auth |",
        "|------|--------|---------|------|",
    ]
    for path, methods in sorted((schema or {}).get("paths", {}).items()):
        for method, op in sorted(methods.items()):
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            summary = (op.get("summary") or "").replace("|", "\\|")
            # The app does not declare openapi security schemes per route;
            # derive the auth column from the endpoint family instead:
            # /health and /auth/* (login, register, refresh, reset) accept
            # unauthenticated callers — everything under /api/v1 does not.
            if path in {"/health", "/metrics", "/api/v1/auth/register",
                        "/api/v1/auth/login", "/api/v1/auth/refresh",
                        "/api/v1/auth/forgot-password",
                        "/api/v1/auth/reset-password"}:
                security = "public"
            else:
                security = "jwt or X-API-Key"
            lines.append(
                f"| `{path}` | `{method.upper()}` | {summary} | {security} |"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    # backend/ is the import root for `main:app`.
    import sys

    backend = ROOT / "backend"
    sys.path.insert(0, str(backend))

    from main import app

    schema = app.openapi()

    openapi_path = ROOT / "docs" / "openapi.json"
    openapi_path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")

    api_md_path = ROOT / "docs" / "API.md"
    api_md_path.write_text(render_api_md(schema) + "\n")

    count = sum(
        1
        for methods in schema.get("paths", {}).values()
        for m in methods
        if m in {"get", "post", "put", "patch", "delete"}
    )
    print(f"openapi: {count} operations -> docs/openapi.json + docs/API.md")


if __name__ == "__main__":
    main()
