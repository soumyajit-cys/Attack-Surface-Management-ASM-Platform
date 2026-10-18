"""docs/openapi.json + docs/API.md must match the running app.

Both are generated (`make openapi`). This test regenerates them in memory
from app.openapi() and compares against the committed files, failing with
the regeneration command when they drift. Doc-only: no DB, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

from main import app

ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "docs"
OPENAPI_FILE = DOCS / "openapi.json"
API_MD = DOCS / "API.md"


def generate_openapi() -> str:
    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"


def generate_api_md() -> str:
    from scripts.export_openapi import render_api_md

    return render_api_md(app.openapi()) + "\n"


def test_committed_openapi_json_is_current():
    assert OPENAPI_FILE.exists(), (
        "docs/openapi.json missing -- run `make openapi` and commit it"
    )
    committed = OPENAPI_FILE.read_text()
    current = generate_openapi()
    assert committed == current, (
        "docs/openapi.json is stale relative to the routes in main.app -- "
        "run `make openapi` and commit the regenerated files"
    )


def test_committed_api_md_is_current():
    assert API_MD.exists(), "docs/API.md missing -- run `make openapi` and commit it"
    committed = API_MD.read_text()
    current = generate_api_md()
    assert committed == current, (
        "docs/API.md is stale relative to the routes in main.app -- "
        "run `make openapi` and commit the regenerated files"
    )
