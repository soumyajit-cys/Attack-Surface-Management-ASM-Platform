"""v3 scanner-module tests: registry discovery of the plugin modules."""

import sys

import pytest

from app.scanning.registry import registry, ScanPhase


def _evict_scanner_modules() -> None:
    """Drop cached scanner_modules imports so discovery re-executes them."""
    for name in [n for n in sys.modules if n == "scanner_modules" or n.startswith("scanner_modules.")]:
        del sys.modules[name]


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Reset the global registry so discovery runs fresh."""
    _evict_scanner_modules()
    registry._entries.clear()
    registry._discovered = False
    yield
    _evict_scanner_modules()
    registry._entries.clear()
    registry._discovered = False


class TestScannerModuleDiscovery:
    def test_discovers_port_ssl_header_modules(self):
        mods = registry.get_modules()
        names = {m.name for m in mods}
        assert names == {"port_scan", "ssl_scan", "header_scan"}

    def test_phase_assignment(self):
        by_phase = {
            m.name: m.phase
            for m in registry.get_modules()
        }
        assert by_phase["port_scan"] == ScanPhase.PORT
        assert by_phase["ssl_scan"] == ScanPhase.SSL
        assert by_phase["header_scan"] == ScanPhase.HEADER

    def test_phase_filter(self):
        port_mods = registry.get_modules(phase=ScanPhase.PORT)
        assert [m.name for m in port_mods] == ["port_scan"]

    def test_scan_context_contract(self):
        """Modules accept a single ScanContext positional arg (no persistence)."""
        import inspect

        for mod in registry.get_modules():
            params = inspect.signature(mod.run).parameters
            assert list(params) == ["ctx"]

    def test_modules_wrap_legacy_scanners(self):
        """The plugin modules call the existing scanner functions."""
        import scanner_modules.port_scan as port_module
        import scanner_modules.ssl_scan as ssl_module
        import scanner_modules.header_scan as header_module

        assert "scan_ports" in dir(port_module)
        assert "analyze_ssl" in dir(ssl_module)
        assert "analyze_headers" in dir(header_module)