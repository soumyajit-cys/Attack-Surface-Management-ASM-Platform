"""Release contract: one semantic version, honest changelog, working gate.

The version lives in exactly one place — the VERSION file at the repo root —
and `backend/pyproject.toml` / `frontend/package.json` must mirror it. The
tagging ritual (see docs/OPERATIONS.md § Tags and releases) cuts `v<version>`
tags from main; nothing in CI auto-bumps.

Doc-only tests: no DB, no network.
"""

from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"
PYPROJECT = ROOT / "backend" / "pyproject.toml"
PKG_JSON = ROOT / "frontend" / "package.json"
CHANGELOG = ROOT / "CHANGELOG.md"
MAKEFILE = ROOT / "Makefile"


def _version() -> str:
    assert VERSION_FILE.exists(), (
        "VERSION file missing - the single semantic-version source; create it "
        "(e.g. '0.1.0\\n') before tagging"
    )
    return VERSION_FILE.read_text().strip()


def test_versions_match_single_source():
    v = _version()
    pyproject = tomllib.loads(PYPROJECT.read_text())["project"]["version"]
    pkg = __import__("json").loads(PKG_JSON.read_text())["version"]
    assert pyproject == v, f"backend/pyproject.toml version {pyproject!r} != VERSION {v!r}"
    assert pkg == v, f"frontend/package.json version {pkg!r} != VERSION {v!r}"
    assert v.count(".") == 2, f"VERSION {v!r} is not a plain semver x.y.z"


def test_changelog_exists_and_has_unreleased():
    assert CHANGELOG.exists(), "CHANGELOG.md missing (Keep a Changelog format)"
    text = CHANGELOG.read_text()
    assert "## [Unreleased]" in text, "CHANGELOG.md needs an '## [Unreleased]' section"
    assert "Keep a Changelog" in text, "CHANGELOG.md should reference its format"


def test_release_check_target_defined():
    makefile = MAKEFILE.read_text()
    assert "release-check:" in makefile, (
        "Makefile is missing the release-check target (make check + audit + "
        "lockfile checks)"
    )


def test_semver_in_changelog_header_matches_version():
    """When a release is cut, the changelog header must match VERSION.

    Unreleased content may exist alongside a released header; every
    released header must be a proper x.y.z, and the newest one must equal
    VERSION until 'Unreleased' is promoted into it.
    """
    import re

    text = CHANGELOG.read_text()
    headers = re.findall(r"^## \[([^\]]+)\]", text, re.M)
    assert headers, "no release headers in CHANGELOG.md"
    semver_headers = [h for h in headers if h != "Unreleased"]
    for h in semver_headers:
        assert re.fullmatch(r"\d+\.\d+\.\d+", h), f"non-semver header: {h!r}"
    if len(headers) > 1 or (headers and headers[0] != "Unreleased"):
        # newest semver header must equal VERSION (releases are cut off main
        # after bumping it -- see docs/OPERATIONS.md tag ritual)
        assert semver_headers[0] == _version(), (
            f"newest changelog header {semver_headers[0]!r} != VERSION {_version()!r}`
            " — promote the Unreleased section and bump VERSION together"
        )
