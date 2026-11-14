"""v3 tls_depth (ssl_risk) tests."""

import math
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from services.scanner.ssl_risk import assess_ssl_risk, LEGACY_PROTOCOLS_TESTABLE, CA_BUNDLE_AVAILABLE


class TestExpiryTiers:
    def _make_ssl_data(self, now, days_remaining):
        expires_at = now + timedelta(days=days_remaining)
        return {
            "host": "example.com",
            "expired": days_remaining <= 0,
            "expires_at": expires_at,
            "self_signed": False,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
        }

    def test_exactly_30_days_no_finding(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 30)
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 0

    def test_29d23h_low(self):
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=29, hours=23)
        data = self._make_ssl_data(now, 0)
        data["expires_at"] = expires_at
        data["expired"] = False
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "low"

    def test_exactly_14_days_low(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 14)
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "low"

    def test_13d23h_medium(self):
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=13, hours=23)
        data = self._make_ssl_data(now, 0)
        data["expires_at"] = expires_at
        data["expired"] = False
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "medium"

    def test_exactly_7_days_medium(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 7)
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "medium"

    def test_6d23h_high(self):
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=6, hours=23)
        data = self._make_ssl_data(now, 0)
        data["expires_at"] = expires_at
        data["expired"] = False
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "high"

    def test_0_days_expired(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 0)
        data["expired"] = True
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        assert any("Expired" in f.get("title", "") for f in findings)

    def test_negative_days_expired(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, -1)
        data["expired"] = True
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        assert any("Expired" in f.get("title", "") for f in findings)

    def test_risk_level_consistent_with_tier(self):
        # At 29 days, finding=low, risk_level should be low (not high)
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 29)
        result = assess_ssl_risk(data, now=now)
        assert result["risk_level"] != "high"

    def test_no_ssl_tls13_info_finding(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 45)
        data["tls_version"] = "TLSv1.3"
        result = assess_ssl_risk(data)
        findings = result["findings"]
        assert not any("TLS 1.3 Supported" in f.get("title", "") for f in findings)

    def test_chain_code_20_incomplete(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 45)
        data["verify_code"] = 20
        result = assess_ssl_risk(data)
        findings = result["findings"]
        assert any("Incomplete" in f.get("title", "") for f in findings)

    def test_chain_code_19_untrusted(self):
        now = datetime.now(timezone.utc)
        data = self._make_ssl_data(now, 45)
        data["verify_code"] = 19
        result = assess_ssl_risk(data)
        findings = result["findings"]
        if CA_BUNDLE_AVAILABLE:
            assert any("Untrusted Root" in f.get("title", "") for f in findings)
        else:
            assert not any("Untrusted Root" in f.get("title", "") for f in findings)

    def test_legacy_protocols_testable_is_bool(self):
        assert isinstance(LEGACY_PROTOCOLS_TESTABLE, bool)

    def test_ca_bundle_available_is_bool(self):
        assert isinstance(CA_BUNDLE_AVAILABLE, bool)


class TestSslScanRiskLevelConsistency:
    def test_chain_code_19_maps_to_untrusted_root(self):
        """Verify code 19 → untrusted root finding (real mapping, not constant)."""
        from services.scanner.ssl_risk import assess_ssl_risk
        now = datetime.now(timezone.utc)
        data = {
            "host": "example.com",
            "expired": False,
            "expires_at": now + timedelta(days=45),
            "self_signed": False,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "verify_code": 19,
        }
        # Only flag if CA bundle available
        from services.scanner.ssl_risk import CA_BUNDLE_AVAILABLE
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        untrusted = [f for f in findings if "Untrusted Root" in f.get("title", "")]
        if CA_BUNDLE_AVAILABLE:
            assert len(untrusted) == 1
        else:
            assert len(untrusted) == 0

    def test_chain_code_20_maps_to_incomplete_chain(self):
        """Verify code 20 → incomplete chain finding (real mapping, not constant)."""
        from services.scanner.ssl_risk import assess_ssl_risk
        now = datetime.now(timezone.utc)
        data = {
            "host": "example.com",
            "expired": False,
            "expires_at": now + timedelta(days=45),
            "self_signed": False,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "verify_code": 20,
        }
        result = assess_ssl_risk(data, now=now)
        findings = result["findings"]
        incomplete = [f for f in findings if "Incomplete" in f.get("title", "")]
        assert len(incomplete) == 1

    def test_ssl_scan_risk_level_not_unknown(self):
        """ssl_scanner risk_level should be computed, not 'unknown'."""
        # This tests the _calculate_risk_level function
        from services.scanner.ssl_scanner import _calculate_risk_level
        assert _calculate_risk_level(False, False, False, "TLSv1.3") == "low"
        assert _calculate_risk_level(True, False, False, "TLSv1.3") == "critical"
        assert _calculate_risk_level(False, True, False, "TLSv1.3") == "high"
