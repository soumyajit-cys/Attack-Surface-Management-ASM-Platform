"""v3 scanner-module tests: registry discovery of the plugin modules."""

import pytest

from app.scanning.registry import registry, ScanPhase


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Reset the global registry so discovery runs fresh."""
    registry._entries.clear()
    registry._discovered = False
    yield
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
        """Modules accept a ScanContext and return a dict (no persistence)."""
        from app.scanning.context import ScanContext
        from types import SimpleNamespace

        ctx = ScanContext(
            domain="example.com",
            pinned_ip="93.184.216.34",
            org_id=1,
            scan_id=1,
            db=SimpleNamespace(),
            config={},
        )

        import asyncio

        for mod in registry.get_modules():
            if mod.name == "port_scan":
                result = asyncio.run(mod.run(ctx))
                assert isinstance(result, dict)
                assert "ports" in result

    def test_modules_wrap_legacy_scanners(self):
        """The plugin modules call the existing scanner functions."""
        import scanner_modules.port_scan as port_module
        import scanner_modules.ssl_scan as ssl_module
        import scanner_modules.header_scan as header_module

        assert "scan_ports" in dir(port_module)
        assert "analyze_ssl" in dir(ssl_module)
        assert "analyze_headers" in dir(header_module)