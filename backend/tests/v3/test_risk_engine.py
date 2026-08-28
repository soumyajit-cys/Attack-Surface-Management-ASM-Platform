"""v3 scoring tests: risk engine upgrades (exposure, KEV cache path, regex)."""

from datetime import datetime, timezone

from models import Finding, RiskScore, Asset
from services.scoring import risk_engine
from services.scoring.risk_engine import (
    CVE_RE,
    calculate_risk,
    cisa_kev_cache_path,
    recalculate_asset_risk_score,
)


class TestCalculateRisk:
    def test_baseline_high_internet_dev(self):
        score = calculate_risk("high", exposure="internet", asset_criticality="dev")
        assert score == round(7.0 * 1.5 * 1.0 * 0.8, 1)

    def test_internal_exposure_is_cheaper(self):
        internet = calculate_risk("critical", exposure="internet", asset_criticality="prod")
        internal = calculate_risk("critical", exposure="internal", asset_criticality="prod")
        assert internal < internet

    def test_case_insensitive(self):
        assert calculate_risk("HIGH", "INTERNET", "DEV") == calculate_risk(
            "high", "internet", "dev"
        )

    def test_score_capped_at_10(self):
        score = calculate_risk(
            "critical",
            exposure="internet",
            asset_criticality="prod",
            is_kev=True,
        )
        assert score <= 10.0

    def test_unknown_exposure_maps_to_1(self):
        assert calculate_risk("low", exposure="dmz-beyond") == round(2.0 * 1.0 * 1.0 * 0.8, 1)


class TestCVERegex:
    def test_matches_standard_cve(self):
        assert CVE_RE.search("This is CVE-2024-1234 in scope").group(0).upper() == "CVE-2024-1234"

    def test_matches_seven_digit_cve(self):
        assert CVE_RE.search("CVE-2025-1234567").group(0).upper() == "CVE-2025-1234567"

    def test_no_match(self):
        assert CVE_RE.search("not a cve here") is None


class TestKEVCachePath:
    def test_default_tmp_dir(self):
        path = cisa_kev_cache_path()
        assert path.endswith("cisa_kev_cache.json")

    def test_honors_settings_dir(self, monkeypatch):
        class FakeSettings:
            kev_cache_dir = "/tmp/sentinelasm-test-kev"

        monkeypatch.setattr("app.core.config.settings", FakeSettings())
        path = cisa_kev_cache_path()
        assert path == "/tmp/sentinelasm-test-kev/cisa_kev_cache.json"


class TestRecalculateAssetRisk:
    def test_uses_asset_exposure(self, db, org_factory):
        org, user = org_factory("Risk Org", "risk_org", "risk_org@test.com")

        asset = Asset(
            organization_id=org.id,
            name="risk.example.com",
            criticality="prod",
            exposure="internal",  # exposed nowhere, cheaper score
        )
        db.add(asset)
        db.flush()

        finding = Finding(
            organization_id=org.id,
            asset_id=asset.id,
            title="Open port 22",
            severity="high",
            category="general",
        )
        db.add(finding)

        score = recalculate_asset_risk_score(db, asset.id)
        assert score == round(7.0 * 0.8 * 1.5 * 0.8, 1)  # internal * prod * conf

        rs = db.query(RiskScore).filter(RiskScore.asset_id == asset.id).first()
        assert rs is not None
        assert rs.exposure == 0.8  # EXPOSURE_MULTIPLIER["internal"]

    def test_explicit_exposure_overrides_asset(self, db, org_factory):
        org, user = org_factory("Risk Org2", "risk_org2", "risk_org2@test.com")
        asset = Asset(
            organization_id=org.id,
            name="exposed.example.com",
            criticality="dev",
            exposure="internal",
        )
        db.add(asset)
        db.flush()

        db.add(Finding(
            organization_id=org.id,
            asset_id=asset.id,
            title="Crit vuln",
            severity="critical",
            category="vulnerability",
        ))

        score = recalculate_asset_risk_score(db, asset.id, exposure="internet")
        assert score == round(9.0 * 1.5 * 1.0 * 0.8, 1)  # internet mult, critical

    def test_no_findings_returns_zero(self, db, org_factory):
        org, user = org_factory("Risk Org3", "risk_org3", "risk_org3@test.com")
        asset = Asset(organization_id=org.id, name="clean.example.com")
        db.add(asset)
        db.flush()

        assert recalculate_asset_risk_score(db, asset.id) == 0.0

    def test_finding_age_decays_score(self, db, org_factory):
        from datetime import timedelta

        org, user = org_factory("Risk Org4", "risk_org4", "risk_org4@test.com")
        asset = Asset(organization_id=org.id, name="old.example.com", criticality="dev")
        db.add(asset)
        db.flush()

        old = Finding(
            organization_id=org.id,
            asset_id=asset.id,
            title="Old high",
            severity="high",
            category="general",
            created_at=datetime.now(timezone.utc) - timedelta(days=90),
        )
        db.add(old)
        db.flush()

        fresh_asset = Asset(organization_id=org.id, name="fresh.example.com", criticality="dev")
        db.add(fresh_asset)
        db.flush()
        db.add(Finding(
            organization_id=org.id,
            asset_id=fresh_asset.id,
            title="Fresh high",
            severity="high",
            category="general",
            created_at=datetime.now(timezone.utc),
        ))

        old_score = recalculate_asset_risk_score(db, asset.id)
        fresh_score = recalculate_asset_risk_score(db, fresh_asset.id)
        assert old_score < fresh_score


class TestKevBypass:
    def test_kev_lookup_does_not_crash_on_network_failure(self, monkeypatch):
        def boom(cve_id):
            raise AssertionError("should not hit network")

        monkeypatch.setattr(risk_engine, "_fetch_cisa_kev", lambda: set())
        assert risk_engine.is_cisa_kev("CVE-2024-9999") is False