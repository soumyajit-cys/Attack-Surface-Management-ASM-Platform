"""Shared fixtures for v3 tests."""

import sys

import pytest

from app.scanning.registry import registry


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Snapshot and restore registry state without permanent sys.modules mutation."""
    saved_modules = {
        n: m for n, m in sys.modules.items()
        if n == "scanner_modules" or n.startswith("scanner_modules.")
    }
    saved_entries = dict(registry._entries)
    saved_discovered = registry._discovered
    saved_failed = dict(registry._failed_imports)

    yield

    # Remove any new scanner_modules entries added during the test
    for n in list(sys.modules):
        if (n == "scanner_modules" or n.startswith("scanner_modules.")) and n not in saved_modules:
            del sys.modules[n]
    # Restore original modules
    sys.modules.update(saved_modules)
    # Restore registry state
    registry._entries.clear()
    registry._entries.update(saved_entries)
    registry._discovered = saved_discovered
    registry._failed_imports.clear()
    registry._failed_imports.update(saved_failed)
