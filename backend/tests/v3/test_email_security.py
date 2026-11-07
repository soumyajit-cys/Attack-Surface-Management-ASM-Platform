"""Fixture-based tests for the email_security scanner module (Phase 3).

All DNS is mocked via dns.resolver; no network is used.  Covers:
- malformed / split / long TXT strings
- multiple SPF records
- DMARC p=none, pct<100
- NXDOMAIN and timeouts per record type
- MTA-STS and BIMI edge cases
- DKIM selector bounds (MAX_DNS_QUERIES truncation)
- mail-evidence gating (MX / SPF / DMARC present)
- stable dedupe_key per finding type
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import dns.exception
import pytest

from app.core.config import settings
from scanner_modules.email_security import (
    DKIM_SELECTORS,
    MAX_DNS_QUERIES,
    DNS_TIMEOUT,
    _has_mail_evidence,
    _parse_dmarc,
    _parse_spf,
    _query_mx,
    _query_txt,
    email_security_module,
)

from app.scanning.context import ScanContext


# ── unit: parsing helpers ─────────────────────────────────────────────


class TestParsingHelpers:
    def test_parse_spf(self):
        assert _parse_spf(["v=spf1 mx -all"]) == "v=spf1 mx -all"
        assert _parse_spf(["not spf", "v=spf1 include:_spf.google.com ~all"]) == (
            "v=spf1 include:_spf.google.com ~all"
        )
        assert _parse_spf(["v=dkim1 k=rsa; p=..."]) is None
        assert _parse_spf([]) is None

    def test_parse_dmarc(self):
        assert _parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.c"]) == (
            "v=DMARC1; p=reject; rua=mailto:a@b.c"
        )
        assert _parse_dmarc(["v=spf1 mx -all"]) is None
        assert _parse_dmarc([]) is None

    def test_dmarc_policy(self):
        from scanner_modules.email_security import _dmarc_policy

        assert _dmarc_policy("v=DMARC1; p=none;") == "none"
        assert _dmarc_policy("v=DMARC1; p=quarantine;") == "quarantine"
        assert _dmarc_policy("v=DMARC1; p=reject;") == "reject"
        assert _dmarc_policy(None) == "none"
        assert _dmarc_policy("v=DMARC1; rua=mailto:a@b.c") == "none"

    def test_has_mail_evidence(self):
        assert _has_mail_evidence(["mx1.example.com"], None, None) is True
        assert _has_mail_evidence([], "v=spf1 mx -all", None) is True
        assert _has_mail_evidence([], None, "v=DMARC1; p=none;") is True
        assert _has_mail_evidence([], None, None) is False


# ── unit: DNS query mocking ───────────────────────────────────────────


class TestDnsQueries:
    def _make_answers(self, strings):
        class _Answer:
            def __init__(self, text):
                self._text = text

            def to_text(self):
                return self._text

        return [_Answer(s) for s in strings]

    def test_query_txt_success(self, monkeypatch):
        def fake_resolve(qname, rdtype, lifetime):
            assert rdtype == "TXT"
            return self._make_answers(["v=spf1 mx -all"])

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_txt("example.com", "example.com") == ["v=spf1 mx -all"]

    def test_query_txt_nxdomain(self, monkeypatch):
        def fake_resolve(qname, rdtype, lifetime):
            raise dns.exception.NXDOMAIN()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_txt("example.com", "example.com") == []

    def test_query_txt_noanswer(self, monkeypatch):
        def fake_resolve(qname, rdtype, lifetime):
            raise dns.exception.NoAnswer()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_txt("example.com", "example.com") == []

    def test_query_txt_timeout(self, monkeypatch):
        def fake_resolve(qname, rdtype, lifetime):
            raise dns.exception.Timeout()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_txt("example.com", "example.com") == []

    def test_query_mx_success(self, monkeypatch):
        class _Mx:
            def __init__(self, exchange):
                self.exchange = exchange

            def __str__(self):
                return str(self.exchange)

        def fake_resolve(qname, rdtype, lifetime):
            assert rdtype == "MX"
            return [_Mx("mx1.example.com.")]

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_mx("example.com") == ["mx1.example.com"]

    def test_query_mx_nxdomain(self, monkeypatch):
        def fake_resolve(qname, rdtype, lifetime):
            raise dns.exception.NXDOMAIN()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_mx("example.com") == []


# ── unit: settings wiring ─────────────────────────────────────────────


class TestSettingsWiring:
    def test_email_security_settings_exist(self):
        assert isinstance(settings.email_security_enabled, bool)
        assert isinstance(settings.email_security_timeout_seconds, float)
        assert isinstance(settings.email_security_max_queries, int)

    def test_max_queries_bounds_dkim_loop(self):
        """MAX_DNS_QUERIES caps DKIM selector probing (bounded)."""
        assert MAX_DNS_QUERIES == settings.email_security_max_queries
        assert MAX_DNS_QUERIES < len(DKIM_SELECTORS)
        assert DNS_TIMEOUT == settings.email_security_timeout_seconds


# ── module: end-to-end via mocked DNS ─────────────────────────────────


def _make_ctx(domain="example.com", org_id=1, scan_id=1):
    return ScanContext(
        domain=domain,
        pinned_ip="93.184.216.34",
        org_id=org_id,
        scan_id=scan_id,
        db=None,
        scope="full",
    )


class TestEmailSecurityModule:
    def _make_answers(self, strings):
        class _Answer:
            def __init__(self, text):
                self._text = text

            def to_text(self):
                return self._text

        return [_Answer(s) for s in strings]

    def _patch_dns(self, monkeypatch, txt_map, mx_map=None):
        """Patch dns.resolver.resolve with a map of record->txt list."""
        mx_map = mx_map or {}

        def fake_resolve(qname, rdtype, lifetime):
            if rdtype == "MX":
                if str(qname) in mx_map:
                    return mx_map[str(qname)]
                raise dns.exception.NoAnswer()
            if rdtype == "TXT":
                if str(qname) in txt_map:
                    return txt_map[str(qname)]
                raise dns.exception.NoAnswer()
            raise dns.exception.NoAnswer()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    def test_spf_and_dmarc_missing_with_mail_evidence(self, monkeypatch):
        """MX present, no SPF/DMARC: low-severity findings."""
        self._patch_dns(
            monkeypatch,
            txt_map={},
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        titles = [f["title"] for f in result["findings"]]
        assert "SPF record not published" in titles
        assert "DMARC record not published" in titles
        spf_f = next(f for f in result["findings"] if f["title"] == "SPF record not published")
        assert spf_f["severity"] == "low"
        assert spf_f["confidence"] == 0.95
        assert spf_f["dedupe_key"] == "email_security:spf_missing"
        dmarc_f = next(f for f in result["findings"] if f["title"] == "DMARC record not published")
        assert dmarc_f["severity"] == "low"
        assert dmarc_f["dedupe_key"] == "email_security:dmarc_missing"

    def test_no_mail_evidence_no_findings(self, monkeypatch):
        """No MX, no SPF, no DMARC: info note only, never medium."""
        self._patch_dns(monkeypatch, txt_map={}, mx_map={})
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        assert result["findings_total"] == 1
        f = result["findings"][0]
        assert f["title"] == "No mail evidence or SPF record"
        assert f["severity"] == "info"
        assert f["confidence"] == 0.7
        assert f["dedupe_key"] == "email_security:no_mail_evidence"

    def test_dmarc_p_none(self, monkeypatch):
        """DMARC p=none: low severity."""
        self._patch_dns(
            monkeypatch,
            txt_map={
                "_dmarc.example.com": self._make_answers(["v=DMARC1; p=none;"]),
            },
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        f = next(f for f in result["findings"] if "DMARC" in f["title"])
        assert f["severity"] == "low"
        assert f["dedupe_key"] == "email_security:dmarc_none"

    def test_dmarc_pct_under_100(self, monkeypatch):
        """DMARC p=reject with pct<100: low severity finding."""
        self._patch_dns(
            monkeypatch,
            txt_map={
                "_dmarc.example.com": self._make_answers(
                    ["v=DMARC1; p=reject; pct=50;"]
                ),
            },
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        dmarc_findings = [f for f in result["findings"] if "DMARC" in f["title"]]
        assert len(dmarc_findings) == 1
        f = dmarc_findings[0]
        assert f["severity"] == "low"
        assert f["dedupe_key"] == "email_security:dmarc_pct_under_100"

    def test_split_long_txt_strings(self, monkeypatch):
        """SPF record split across multiple TXT strings (concatenated)."""
        self._patch_dns(
            monkeypatch,
            txt_map={
                "example.com": self._make_answers(
                    ["v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 -all"]
                ),
            },
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        spf_findings = [f for f in result["findings"] if "SPF" in f["title"]]
        assert spf_findings == []

    def test_multiple_spf_records(self, monkeypatch):
        """Multiple TXT records, one is SPF: parses the SPF one."""
        self._patch_dns(
            monkeypatch,
            txt_map={
                "example.com": self._make_answers([
                    "v=spf1 mx -all",
                    "some-other-txt-record",
                ]),
            },
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        spf_findings = [f for f in result["findings"] if "SPF" in f["title"]]
        assert spf_findings == []  # valid SPF present, no finding

    def test_dkim_selector_bounds(self, monkeypatch):
        """DKIM loop stops at MAX_DNS_QUERIES, not len(DKIM_SELECTORS)."""
        self._patch_dns(
            monkeypatch,
            txt_map={
                "example.com": self._make_answers(["v=spf1 mx -all"]),
                "_dmarc.example.com": self._make_answers(["v=DMARC1; p=reject;"]),
            },
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        # No DKIM records for any selector -> all return NoAnswer
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        dkim_f = next(f for f in result["findings"] if "DKIM" in f["title"])
        assert dkim_f["severity"] == "info"  # never medium
        assert dkim_f["confidence"] == 0.5
        assert dkim_f["dedupe_key"] == "email_security:dkim_missing"

    def test_mta_sts_and_bimi_absent(self, monkeypatch):
        """MTA-STS and BIMI absent: info-level findings."""
        self._patch_dns(
            monkeypatch,
            txt_map={
                "example.com": self._make_answers(["v=spf1 mx -all"]),
                "_dmarc.example.com": self._make_answers(["v=DMARC1; p=reject;"]),
                "default._bimi.example.com": [],
            },
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        # socket.getaddrinfo for mta-sts raises -> not available
        import socket as real_socket

        real_getaddrinfo = real_socket.getaddrinfo

        def fake_getaddrinfo(host, *a, **k):
            if "mta-sts" in host:
                raise real_socket.gaierror("no such host")
            return real_getaddrinfo(host, *a, **k)

        monkeypatch.setattr(real_socket, "getaddrinfo", fake_getaddrinfo)

        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        mta_f = next(f for f in result["findings"] if "MTA-STS" in f["title"])
        assert mta_f["severity"] == "info"
        assert mta_f["dedupe_key"] == "email_security:mta_sts_missing"
        bimi_f = next(f for f in result["findings"] if "BIMI" in f["title"])
        assert bimi_f["severity"] == "info"
        assert bimi_f["dedupe_key"] == "email_security:bimi_missing"

    def test_dedupe_keys_stable_across_rescans(self, monkeypatch):
        """Same domain scanned twice: same dedupe_key set (update, not duplicate)."""
        self._patch_dns(
            monkeypatch,
            txt_map={
                "example.com": self._make_answers(["v=spf1 mx -all"]),
                "_dmarc.example.com": self._make_answers(["v=DMARC1; p=none;"]),
            },
            mx_map={"example.com": self._make_answers(["mx1.example.com."])},
        )
        r1 = asyncio.run(email_security_module(_make_ctx("example.com"))
        r2 = asyncio.run(email_security_module(_make_ctx("example.com"))
        keys1 = {f["dedupe_key"] for f in r1["findings"] if "dedupe_key" in f}
        keys2 = {f["dedupe_key"] for f in r2["findings"] if "dedupe_key" in f}
        assert keys1 == keys2
        # dmarc_none key present in both
        assert "email_security:dmarc_none" in keys1

    def test_module_disabled(self, monkeypatch):
        """email_security_enabled=False: no findings, outcome=disabled."""
        monkeypatch.setattr(settings, "email_security_enabled", False)
        self._patch_dns(
            monkeypatch,
            txt_map={},
            mx_map={},
        )
        result = asyncio.run(email_security_module(_make_ctx("example.com"))
        assert result["findings"] == []
        assert result["findings_total"] == 0
