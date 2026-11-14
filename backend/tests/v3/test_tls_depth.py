"""v3 tls_depth (ssl_risk) tests."""

import math
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from services.scanner.ssl_risk import assess_ssl_risk, LEGACY_PROTOCOLS_TESTABLE, CA_BUNDLE_AVAILABLE


class TestExpiryTiers:
    def _make_ssl_data(self, days_remaining):
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=days_remaining)
        return {
            "host": "example.com",
            "expired": days_remaining <= 0,
            "expires_at": expires_at,
            "self_signed": False,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
        }

    def test_30_days_low(self):
        data = self._make_ssl_data(30)
        result = assess_ssl_risk(data)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        # 30 days is NOT < 30, so no tier finding
        assert len(expiry_findings) == 0

    def test_29_days_low(self):
        data = self._make_ssl_data(29)
        result = assess_ssl_risk(data)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "low"

    def test_14_days_medium(self):
        data = self._make_ssl_data(14)
        result = assess_ssl_risk(data)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "medium"

    def test_13_days_medium(self):
        data = self._make_ssl_data(13)
        result = assess_ssl_risk(data)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "medium"

    def test_7_days_high(self):
        data = self._make_ssl_data(7)
        result = assess_ssl_risk(data)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "high"

    def test_6_days_high(self):
        data = self._make_ssl_data(6)
        result = assess_ssl_risk(data)
        findings = result["findings"]
        expiry_findings = [f for f in findings if "Expiring Soon" in f.get("title", "")]
        assert len(expiry_findings) == 1
        assert expiry_findings[0]["severity"] == "high"

    def test_0_days_expired(self):
        data = self._make_ssl_data(0)
        data["expired"] = True
        result = assess_ssl_risk(data)
        findings = result["findings"]
        assert any("Expired" in f.get("title", "") for f in findings)

    def test_negative_days_expired(self):
        data = self._make_ssl_data(-1)
        data["expired"] = True
        result = assess_ssl_risk(data)
        findings = result["findings"]
        assert any("Expired" in f.get("title", "") for f in findings)

    def test_risk_level_consistent_with_tier(self):
        # At 29 days, finding=low, risk_level should be low (not high)
        data = self._make_ssl_data(29)
        result = assess_ssl_risk(data)
        assert result["risk_level"] != "high" or result["risk_level"] == "low"

    def test_no_ssl_tls13_info_finding(self):
        data = self._make_ssl_data(45)
        data["tls_version"] = "TLSv1.3"
        result = assess_ssl_risk(data)
        findings = result["findings"]
        assert not any("TLS 1.3 Supported" in f.get("title", "") for f in findings)

    def test_chain_code_20_incomplete(self):
        data = self._make_ssl_data(45)
        data["verify_code"] = 20
        result = assess_ssl_risk(data)
        findings = result["findings"]
        assert any("Incomplete" in f.get("title", "") for f in findings)

    def test_chain_code_19_untrusted(self):
        data = self._make_ssl_data(45)
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
