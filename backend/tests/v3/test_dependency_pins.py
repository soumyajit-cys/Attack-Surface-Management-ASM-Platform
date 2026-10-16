"""Locked-dependency guard: the installed fastapi must equal uv.lock.

FastAPI >=0.143 nests included routers (_IncludedRouter), which silently
disables slowapi's per-route handler lookup. The pin in pyproject.toml is
only as good as its enforcement: this test fails the suite if the runtime
drifts from the lockfile. No network, no DB.
"""

from pathlib import Path


def _locked_version(name: str) -> str:
    root = Path(__file__).resolve().parents[2]
    text = (root / "uv.lock").read_text()
    current = None
    for line in text.splitlines():
        if line.strip() == f'name = "{name}"':
            current = "hit"
        elif current == "hit" and line.strip().startswith("version = "):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError(f"{name} not found in uv.lock")


def test_installed_fastapi_matches_lockfile():
    import fastapi

    assert fastapi.__version__ == _locked_version("fastapi"), (
        f"installed fastapi {fastapi.__version__} != "
        f"locked {_locked_version('fastapi')}: re-run `make lock` and "
        "tests/v3/test_rate_limits.py before bumping (see pyproject comment)"
    )
