"""README drift guard.

The README's configuration table is the operator-facing contract: it must
document every Settings field. This test fails when a new Settings field is
added without a README row (or a row is renamed away from the field name),
exactly like the .env.example drift test enforces the operator surface.
Doc-only, no DB, no network.
"""

from pathlib import Path

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[3]
README = ROOT / "README.md"


def test_readme_config_table_covers_every_settings_field():
    text = README.read_text()
    documented = {line.strip().upper() for line in text.splitlines()
                  if line.strip().startswith("`") and "`" in line.strip()[1:]}

    # A row documents a field when the field name appears in back-ticks
    # (multi-var rows like `SMTP_HOST` / `_PORT` still match on any token).
    tokens = set()
    for line in text.splitlines():
        if line.startswith("|") or "`" in line:
            tokens.update(tok.strip("` ").upper() for tok in line.split("`"))
    tokens.discard("")

    missing = [
        field.upper()
        for field in Settings.model_fields
        if field.upper() not in tokens
    ]
    assert not missing, (
        "README config table is missing Settings fields — add a row with the "
        "variable name in back-ticks: " + ", ".join(missing)
    )


def test_readme_does_not_document_stale_test_counts():
    """Point-in-time counts rot; the README must not hardcode them."""
    text = README.read_text()
    for stale in ["422 tests", "791 kB", "python-jose", "docker-compose.yml  # Compose stack (WIP)"]:
        assert stale not in text, f"README contains stale claim: {stale!r}"


def test_readme_links_security_docs():
    text = README.read_text()
    assert "docs/threat-model.md" in text
    assert "[MIT](LICENSE)" in text or "LICENSE" in text


def test_readme_contains_no_demo_credentials():
    """The demo password is printed once by scripts/seed_demo.py; the README
    must never document a working credential (Passw0rd-style constants)."""
    text = README.read_text()
    assert "Passw0rd" not in text, (
        "README documents a real demo credential — the seeder now prints a "
        "one-time random password instead; remove the constant"
    )
