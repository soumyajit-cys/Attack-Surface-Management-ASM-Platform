"""Item 5: silent failures must be loud.

(a) Scanner registry import failures are logged and surfaced as
    ``unavailable_phases`` — in every scan summary AND in the scan detail
    API response, with a warm-up at app startup.
(b) domain_service's pinned-resolve fallback logs a warning naming the
    exception type (no bare ``except: pass``).
(c) The ``pdf_unavailable`` error returns a STATIC message, never the
    internal exception text (``str(exc)`` leaked fpdf2 install hints).

Hermetic: no network, no TLS, no celery.
"""

import asyncio
import importlib
import logging
import sys

import pytest


# ══ (a) scanner registry ══════════════════════════════════════════════════════

REGISTRY_LOGGER = "app.scanning.registry"


@pytest.fixture()
def fresh_registry():
    """Reset the global registry before AND after each test."""
    from app.scanning.registry import registry

    registry._entries.clear()
    registry._discovered = True  # unit tests manage registration manually
    yield registry
    registry._entries.clear()
    registry._discovered = False


@pytest.fixture()
def scan_detail(client, db, org_factory):
    """Org with one completed scan + bearer auth for the org admin."""
    from models import Asset, ScanHistory

    org, _ = org_factory("SilentSF Org", "silentsf", "silentsf@example.com")
    asset = Asset(organization_id=org.id, name="sf-asset.example.com")
    db.add(asset)
    db.flush()
    scan = ScanHistory(
        organization_id=org.id,
        asset_id=asset.id,
        target="sf-asset.example.com",
        status="completed",
        scope="full",
    )
    db.add(scan)
    db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "silentsf", "password": "password123"},
    )
    assert response.status_code == 200, response.text
    return {
        "auth": {"Authorization": f"Bearer {response.json()['access_token']}"},
        "scan_id": scan.id,
    }


class TestRegistryUnavailablePhases:
    def test_enumerates_pipeline_phases_without_modules(self, fresh_registry):
        from app.scanning.registry import ScannerEntry, ScanPhase

        async def noop(ctx):
            return {}

        fresh_registry.register(
            ScannerEntry(name="p", phase=ScanPhase.PORT, run=noop))

        # Discovery runs via services, not the registry — the pipelined
        # scanner phases are PORT / SSL / HEADER only.
        assert fresh_registry.unavailable_phases() == ["ssl", "header"]

    def test_empty_registry_lists_every_pipeline_phase(self, fresh_registry):
        assert fresh_registry.unavailable_phases() == [
            "port", "ssl", "header"]

    def test_all_registered_means_no_unavailable(self, fresh_registry):
        from app.scanning.registry import ScannerEntry, ScanPhase

        async def noop(ctx):
            return {}

        for phase in (ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER):
            fresh_registry.register(
                ScannerEntry(name=phase.value, phase=phase, run=noop))
        assert fresh_registry.unavailable_phases() == []

    def test_failed_import_recorded_and_logged(
            self, fresh_registry, monkeypatch, caplog):
        from app.scanning.registry import ScanPhase

        real_import = importlib.import_module

        def flaky_import(name, *args, **kwargs):
            if name == "scanner_modules.ssl_scan":
                raise RuntimeError("boom: ssl module is broken")
            return real_import(name, *args, **kwargs)

        # Force a REAL re-discovery: drop the cached scanner modules so the
        # module bodies (and their @scanner_module registrations) re-execute.
        for cached in ("scanner_modules.port_scan",
                       "scanner_modules.ssl_scan",
                       "scanner_modules.header_scan"):
            monkeypatch.delitem(sys.modules, cached, raising=False)

        monkeypatch.setattr(
            "app.scanning.registry.importlib.import_module", flaky_import)
        fresh_registry._discovered = False  # let get_modules() discover

        with caplog.at_level(logging.ERROR, logger=REGISTRY_LOGGER):
            port_mods = fresh_registry.get_modules(phase=ScanPhase.PORT)
            ssl_mods = fresh_registry.get_modules(phase=ScanPhase.SSL)

        # port and header registered from the re-discovery; ssl did not
        assert {e.phase.value for e in port_mods} == {"port"}
        assert ssl_mods == []
        assert fresh_registry.unavailable_phases() == ["ssl"]
        assert "scanner_modules.ssl_scan" in fresh_registry.failed_imports
        failures = [
            r for r in caplog.records
            if "Failed to import scanner module" in r.getMessage()
        ]
        assert failures, "a failed module import must be logged"
        assert "scanner_modules.ssl_scan" in failures[0].getMessage()

    def test_warmup_reports_unavailable_at_startup(
            self, fresh_registry, monkeypatch, caplog):
        from app.scanning.registry import ScannerEntry, ScanPhase

        async def noop(ctx):
            return {}

        def stub_discovery(reg):
            # Only port_scan registered; ssl_scan import failed.
            reg.register(
                ScannerEntry(name="port_scan", phase=ScanPhase.PORT, run=noop))
            reg._failed_imports["scanner_modules.ssl_scan"] = (
                "RuntimeError: boom")

        monkeypatch.setattr(
            "app.scanning.registry._discover_scanner_modules", stub_discovery)
        fresh_registry._discovered = False

        with caplog.at_level(logging.WARNING, logger=REGISTRY_LOGGER):
            phases = fresh_registry.warmup()

        assert phases == ["ssl", "header"]
        warnings = [
            r for r in caplog.records
            if "unavailable" in r.getMessage().lower()
        ]
        assert warnings, "startup warm-up must log unavailable phases loudly"
        assert any("ssl" in r.getMessage() for r in warnings)
        assert any(
            "scanner_modules.ssl_scan" in r.getMessage() for r in warnings)


class TestScanSummaryIncludesUnavailablePhases:
    def test_new_summary_always_carries_unavailable_phases(
            self, fresh_registry):
        from app.scanning.registry import ScannerEntry, ScanPhase
        from tasks.discovery_tasks import _new_summary

        async def noop(ctx):
            return {}

        fresh_registry.register(
            ScannerEntry(name="ssl_scan", phase=ScanPhase.SSL, run=noop))

        summary = _new_summary(fresh_registry)

        assert "unavailable_phases" in summary
        assert summary["unavailable_phases"] == ["port", "header"]
        # the rest of the summary shape is unchanged
        assert summary["ports_open"] == 0
        assert summary["nuclei_skipped"] is True


class TestScanDetailSurfacesUnavailablePhases:
    def test_scan_detail_api_includes_unavailable_phases(
            self, client, scan_detail, monkeypatch):
        from app.scanning.registry import ScannerEntry, ScanPhase, registry

        async def noop(ctx):
            return {}

        entry = ScannerEntry(
            name="port_scan", phase=ScanPhase.PORT, run=noop)
        monkeypatch.setattr(registry, "_discovered", True)
        monkeypatch.setattr(registry, "_entries", {entry.name: entry})

        response = client.get(
            f"/api/v1/scans/{scan_detail['scan_id']}",
            headers=scan_detail["auth"],
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["unavailable_phases"] == ["ssl", "header"]

    def test_scan_detail_api_reports_no_unavailable_when_all_mounted(
            self, client, scan_detail, monkeypatch):
        from app.scanning.registry import ScannerEntry, ScanPhase, registry

        async def noop(ctx):
            return {}

        entries = {
            f"{phase.value}_scan": ScannerEntry(
                name=f"{phase.value}_scan", phase=phase, run=noop)
            for phase in (ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER)
        }
        monkeypatch.setattr(registry, "_discovered", True)
        monkeypatch.setattr(registry, "_entries", entries)

        response = client.get(
            f"/api/v1/scans/{scan_detail['scan_id']}",
            headers=scan_detail["auth"],
        )
        assert response.status_code == 200, response.text
        assert response.json()["unavailable_phases"] == []


# ══ (b) domain_service bare except: pass ══════════════════════════════════════

DS_LOGGER = "sentinelasm"


class TestDomainServiceFailureLogging:
    def test_pinned_resolve_failure_warns_with_exception_type(
            self, monkeypatch, caplog):
        from services.discovery import domain_service as ds

        def boom(domain):
            raise OSError("redis pin unavailable")

        monkeypatch.setattr("app.core.ssrf.pinned_resolve", boom)

        def fresh_dns(domain):
            return ["203.0.113.10"]

        monkeypatch.setattr(ds, "resolve_validated_ips", fresh_dns)

        with caplog.at_level(logging.WARNING, logger=DS_LOGGER):
            out = asyncio.run(ds.resolve_domain("fallback.example"))

        # behavior is unchanged: fresh DNS fallback still answers
        assert out == {
            "domain": "fallback.example",
            "ip": "203.0.113.10",
            "pinned": False,
        }
        warnings = [
            r for r in caplog.records
            if "Pinned IP lookup failed" in r.getMessage()
        ]
        assert warnings, "pinned-resolve failure must not be silently dropped"
        assert "OSError" in warnings[0].getMessage()

    def test_pinned_resolve_success_does_not_warn(
            self, monkeypatch, caplog):
        from services.discovery import domain_service as ds

        monkeypatch.setattr(
            "app.core.ssrf.pinned_resolve",
            lambda domain: "93.184.216.34",
        )

        with caplog.at_level(logging.WARNING, logger=DS_LOGGER):
            out = asyncio.run(ds.resolve_domain("pinned.example"))

        assert out == {
            "domain": "pinned.example",
            "ip": "93.184.216.34",
            "pinned": True,
        }
        assert not [
            r for r in caplog.records
            if "Pinned IP lookup failed" in r.getMessage()
        ]


# ══ (c) PDF pdf_unavailable static message ════════════════════════════════════

_STATIC_PDF_MESSAGE = "PDF generation is unavailable on this deployment"


@pytest.fixture()
def pdf_org(client, db, org_factory):
    """Org with one finding + bearer auth (REPORT_EXPORT-scoped dep)."""
    from models import Asset, Finding

    org, _ = org_factory("PdfOrg", "pdforg", "pdforg@example.com")
    asset = Asset(organization_id=org.id, name="pdf-asset.example.com")
    db.add(asset)
    db.flush()
    finding = Finding(
        organization_id=org.id,
        asset_id=asset.id,
        title="pdf finding",
        severity="medium",
    )
    db.add(finding)
    db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "pdforg", "password": "password123"},
    )
    assert response.status_code == 200, response.text
    return {
        "auth": {"Authorization": f"Bearer {response.json()['access_token']}"},
        "finding_id": finding.id,
    }


class TestPdfUnavailableStaticMessage:
    def test_executive_summary_pdf_never_leaks_internal_error(
            self, client, pdf_org, monkeypatch):
        import app.api.v1.reports as reports_mod

        def broken_generate(db, org_id, *, asset_id=None, since=None):
            raise RuntimeError(
                "fpdf2 not installed. Install with: pip install fpdf2")

        monkeypatch.setattr(
            reports_mod, "generate_executive_summary", broken_generate)

        response = client.get(
            "/api/v1/reports/pdf/executive-summary", headers=pdf_org["auth"])

        assert response.status_code == 500, response.text
        error = response.json()["error"]
        assert error["code"] == "pdf_unavailable"
        assert error["message"] == _STATIC_PDF_MESSAGE
        assert "fpdf2" not in response.text

    def test_finding_detail_pdf_never_leaks_internal_error(
            self, client, pdf_org, monkeypatch):
        import app.api.v1.reports as reports_mod

        def broken_generate(db, finding_id):
            raise RuntimeError(
                "fpdf2 not installed. Install with: pip install fpdf2")

        monkeypatch.setattr(
            reports_mod, "generate_finding_detail_pdf", broken_generate)

        response = client.get(
            f"/api/v1/reports/pdf/finding/{pdf_org['finding_id']}",
            headers=pdf_org["auth"],
        )

        assert response.status_code == 500, response.text
        error = response.json()["error"]
        assert error["code"] == "pdf_unavailable"
        assert error["message"] == _STATIC_PDF_MESSAGE
        assert "fpdf2" not in response.text
