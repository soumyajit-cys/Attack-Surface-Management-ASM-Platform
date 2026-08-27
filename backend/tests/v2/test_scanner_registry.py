"""Scanner registry tests: discovery, phase filtering, duplicate detection."""

import pytest

from app.scanning.registry import ScannerRegistry, ScanPhase, ScannerEntry, scanner_module, registry


@pytest.fixture(autouse=True)
def _fresh_registry():
    """Reset the global registry for each test."""
    registry._entries.clear()
    registry._discovered = True  # skip auto-discovery in unit tests
    yield
    registry._entries.clear()
    registry._discovered = False


class TestScannerRegistry:
    def test_register_and_list(self):
        async def noop(ctx):
            return {}

        registry.register(ScannerEntry(name="a", phase=ScanPhase.PORT, run=noop))
        registry.register(ScannerEntry(name="b", phase=ScanPhase.DISCOVERY, run=noop))

        all_mods = registry.list_all()
        assert len(all_mods) == 2
        # Discovery comes before port (enum order).
        assert all_mods[0].phase == ScanPhase.DISCOVERY
        assert all_mods[1].phase == ScanPhase.PORT

    def test_get_modules_filters_by_phase(self):
        async def noop(ctx):
            return {}

        registry.register(ScannerEntry(name="port1", phase=ScanPhase.PORT, run=noop))
        registry.register(ScannerEntry(name="ssl1", phase=ScanPhase.SSL, run=noop))
        registry.register(ScannerEntry(name="port2", phase=ScanPhase.PORT, run=noop, order=1))

        port_mods = registry.get_modules(phase=ScanPhase.PORT)
        assert len(port_mods) == 2
        assert all(m.phase == ScanPhase.PORT for m in port_mods)

        ssl_mods = registry.get_modules(phase=ScanPhase.SSL)
        assert len(ssl_mods) == 1
        assert ssl_mods[0].name == "ssl1"

    def test_get_by_name(self):
        async def noop(ctx):
            return {}

        registry.register(ScannerEntry(name="target", phase=ScanPhase.HEADER, run=noop))
        assert registry.get_by_name("target") is not None
        assert registry.get_by_name("nonexistent") is None

    def test_duplicate_name_raises(self):
        async def noop(ctx):
            return {}

        registry.register(ScannerEntry(name="dup", phase=ScanPhase.PORT, run=noop))
        with pytest.raises(ValueError, match="already registered"):
            registry.register(ScannerEntry(name="dup", phase=ScanPhase.PORT, run=noop))

    def test_order_sorting_within_phase(self):
        async def noop(ctx):
            return {}

        registry.register(ScannerEntry(name="c", phase=ScanPhase.PORT, run=noop, order=3))
        registry.register(ScannerEntry(name="a", phase=ScanPhase.PORT, run=noop, order=1))
        registry.register(ScannerEntry(name="b", phase=ScanPhase.PORT, run=noop, order=2))

        mods = registry.get_modules(phase=ScanPhase.PORT)
        assert [m.name for m in mods] == ["a", "b", "c"]

    def test_scanner_module_decorator(self):
        @scanner_module("decorated_scan", phase="ssl", order=5)
        async def my_scanner(ctx):
            return {"ok": True}

        assert registry.get_by_name("decorated_scan") is not None
        entry = registry.get_by_name("decorated_scan")
        assert entry.phase == ScanPhase.SSL
        assert entry.order == 5

    def test_scan_phase_enum_values(self):
        assert ScanPhase.DISCOVERY.value == "discovery"
        assert ScanPhase.PORT.value == "port"
        assert ScanPhase.SSL.value == "ssl"
        assert ScanPhase.HEADER.value == "header"
