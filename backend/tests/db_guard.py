"""Test-database safety guard (importable module, not conftest)."""

from urllib.parse import urlparse


def assert_safe_test_db(url: str) -> None:
    """Refuse to run unless the DB name looks like a scratch/test DB."""
    parsed = urlparse(url)
    db_name = (parsed.path or "").lstrip("/").split("?")[0]
    if not db_name.startswith(("scratch_", "test_")):
        raise RuntimeError(
            f"Refusing to run tests against database {db_name!r}: "
            "name must start with 'scratch_' or 'test_'"
        )


def assert_safe_test_redis(url: str) -> None:
    """Refuse to flush Redis unless host is local or DB index is a test index."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = (parsed.path or "").lstrip("/")
    db_index = path.split("/")[0] if path else "0"
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    # Allow if host is local OR db index >= 10 (dedicated test index)
    if host not in local_hosts and not (db_index.isdigit() and int(db_index) >= 10):
        raise RuntimeError(
            f"Refusing to flush Redis at {host!r} (db={db_index}): "
            "host must be local or db index >= 10"
        )
