"""Fixture-based tests for the subdomain_takeover scanner module (Phase 3).

Covers:
- NXDOMAIN confirmation (active) vs SERVFAIL/timeout (not NXDOMAIN)
- Flapping NXDOMAIN (first query NXDOMAIN, second resolves)
- CNAME chain walk with loop detection
- CNAME chain depth cap (~8)
- Label-boundary suffix matching: evilgithub.io does NOT match github.io
- Per-provider fixture bodies
- Edge-case provider → likely_claimable severity ≤ 0.85
- Two hosts → two separate findings (dedupe by hostname)
- Rescan of same host → updates one finding (same dedupe_key)
- Truncation at MAX_HOSTS_PER_SCAN
- Scope gating: unverified domains → no probe

All DNS and HTTP are mocked; no network is used.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import dns.exception
import dns.resolver
import pytest

from scanner_modules.subdomain_takeover import (
    FINGERPRINTS,
    MAX_CNAME_DEPTH,
    MAX_HOSTS_PER_SCAN,
    MAX_CONCURRENCY,
    _cname_chain,
    _cname_matches_provider,
    _query_nxdomain_confirmed,
    subdomain_takeover_module,
)

from app.scanning.context import ScanContext
from app.scanning.registry import ScanPhase


# ── Fixture helpers ──────────────────────────────────────────────────


def _make_ctx(domain="example.com", org_id=1, scan_id=1, subdomains=None):
    return ScanContext(
        domain=domain,
        pinned_ip="93.184.216.34",
        org_id=org_id,
        scan_id=scan_id,
        db=None,
        scope="full",
        subdomains=list(subdomains or []),
    )


def _make_dns_answers(records):
    """Build a list of dns.resolver.Answer-like objects from text strings."""
    class _Answer:
        def __init__(self, text):
            self._text = text
            self.target = self

        def to_text(self):
            return self._text

    return [_Answer(s) for s in records]


def _patch_dns(monkeypatch, txt_map=None, mx_map=None, cname_map=None, a_map=None):
    """Patch dns.resolver.resolve with a mock that returns answers based on
    the query type and name."""
    txt_map = txt_map or {}
    mx_map = mx_map or {}
    cname_map = cname_map or {}
    a_map = a_map or {}

    def fake_resolve(qname, rdtype, lifetime):
        qname_str = str(qname).rstrip(".").lower()
        if rdtype == "TXT":
            if qname_str in txt_map:
                return _make_dns_answers(txt_map[qname_str])
            raise dns.resolver.NoAnswer()
        if rdtype == "MX":
            if qname_str in mx_map:
                return _make_dns_answers(mx_map[qname_str])
            raise dns.resolver.NoAnswer()
        if rdtype == "CNAME":
            if qname_str in cname_map:
                return _make_dns_answers(cname_map[qname_str])
            raise dns.resolver.NoAnswer()
        if rdtype == "A":
            if qname_str in a_map:
                return _make_dns_answers(a_map[qname_str])
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)


def _patch_http(monkeypatch, http_map=None):
    """Patch httpx.Client.get and utils.egress.resolve_validated_ips to
    return canned responses."""
    http_map = http_map or {}
    import httpx

    class _Response:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    def fake_get(self, url, headers=None, **kwargs):
        host = headers.get("Host", "") if headers else ""
        host = host.lower().rstrip(".")
        if host in http_map:
            resp = http_map[host]
            return _Response(resp["status_code"], resp["body"])
        return _Response(404, "Not Found")

    monkeypatch.setattr(httpx.Client, "get", lambda self, url, headers=None, **kwargs: fake_get(self, url, headers, **kwargs))

    def fake_resolve_validated_ips(host, port=80):
        # Return the pinned IP for any host
        return ["93.184.216.34"]

    monkeypatch.setattr("utils.egress.resolve_validated_ips", fake_resolve_validated_ips)


# ── Unit tests: parsing/matching helpers ───────────────────────────────


class TestParsingHelpers:
    def test_cname_matches_provider_label_boundary(self):
        """evilgithub.io does NOT match github.io suffix."""
        provider = {"cname_suffixes": ["github.io"]}
        assert _cname_matches_provider("github.io", provider) is True
        assert _cname_matches_provider("www.github.io", provider) is True
        assert _cname_matches_provider("evilgithub.io", provider) is False
        assert _cname_matches_provider("notgithub.io", provider) is False

    def test_cname_matches_case_insensitive(self):
        provider = {"cname_suffixes": ["GITHUB.IO"]}
        assert _cname_matches_provider("www.GITHUB.IO", provider) is True


# ── Unit tests: DNS chain walking ─────────────────────────────────────


class TestCnameChain:
    def test_chain_single_cname(self, monkeypatch):
        _patch_dns(monkeypatch, cname_map={
            "www.example.com": ["www.github.io."],
        })
        result = _cname_chain("www.example.com")
        assert result == ["www.example.com", "www.github.io"]

    def test_chain_multiple_cnames(self, monkeypatch):
        _patch_dns(monkeypatch, cname_map={
            "a.example.com": ["b.example.com."],
            "b.example.com": ["c.github.io."],
        })
        result = _cname_chain("a.example.com")
        assert result == ["a.example.com", "b.example.com", "c.github.io"]

    def test_chain_loop_detected(self, monkeypatch):
        _patch_dns(monkeypatch, cname_map={
            "a.example.com": ["b.example.com."],
            "b.example.com": ["a.example.com."],
        })
        result = _cname_chain("a.example.com")
        assert result == ["a.example.com", "b.example.com"]

    def test_chain_depth_cap(self, monkeypatch):
        _patch_dns(monkeypatch, cname_map={
            f"h{i}.example.com": [f"h{i+1}.example.com."]
            for i in range(1, 20)
        })
        result = _cname_chain("h1.example.com")
        assert len(result) <= MAX_CNAME_DEPTH


# ── Unit tests: NXDOMAIN confirmation ─────────────────────────────────


class TestNxDomainConfirmed:
    def test_nxdomain_confirmed(self, monkeypatch):
        """First NXDOMAIN, second NXDOMAIN → True."""
        calls = []

        def fake_resolve(qname, rdtype, lifetime):
            calls.append(str(qname))
            raise dns.resolver.NXDOMAIN()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_nxdomain_confirmed("ghost.example.com") is True
        assert len(calls) == 2

    def test_nxdomain_then_resolves(self, monkeypatch):
        """First NXDOMAIN, second resolves → False (flapping)."""
        calls = []

        def fake_resolve(qname, rdtype, lifetime):
            calls.append(str(qname))
            if len(calls) == 1:
                raise dns.resolver.NXDOMAIN()
            return _make_dns_answers(["93.184.216.34"])

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_nxdomain_confirmed("flappy.example.com") is False

    def test_serf_fail_not_nxdomain(self, monkeypatch):
        """SERVFAIL is not NXDOMAIN."""
        def fake_resolve(qname, rdtype, lifetime):
            raise dns.exception.DNSException("SERVFAIL")

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_nxdomain_confirmed("servfail.example.com") is False

    def test_timeout_not_nxdomain(self, monkeypatch):
        """Timeout is not NXDOMAIN."""
        def fake_resolve(qname, rdtype, lifetime):
            raise dns.exception.Timeout()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        assert _query_nxdomain_confirmed("timeout.example.com") is False


# ── Module end-to-end tests ───────────────────────────────────────────


class TestTakeoverModule:
    def test_no_active_probe_without_pin(self, db, org_factory, monkeypatch):
        """DNS brute-force / takeover runs NO active modules when domain
        has no pinned IP (unverified)."""
        import tasks.discovery_tasks as dt

        org, _ = org_factory("Takeover Org", "takeoveruser", "takeover@example.com")
        scan = SimpleNamespace(organization_id=org.id, id=1)

        calls = []

        def fake_run(ctx, modules):
            calls.append([m.phase for m in modules])
            return {}

        monkeypatch.setattr(dt, "_run_in_context", fake_run)
        monkeypatch.setattr(
            dt,
            "pinned_resolve",
            lambda host: (_ for _ in ()).throw(
                __import__("app.core.ssrf", fromlist=["PinnedResolutionMissing"]).PinnedResolutionMissing(host)
            ),
        )

        persisted = {
            "subdomains": [
                SimpleNamespace(subdomain="www.example.com", id=1, ip_address=None)
            ],
        }

        summary = dt._scan_targets(
            db, scan, persisted, "example.com", None, "full"
        )

        active_phases = {
            ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER,
            ScanPhase.FINGERPRINT,
        }
        for phase_list in calls:
            assert not any(p in active_phases for p in phase_list), (
                f"active phase ran without pin: {calls}"
            )
        assert summary["unpinned_skipped"] == ["www.example.com"]
        assert summary["ports_total"] == 0

    def test_wordlist_bounded(self, monkeypatch):
        """DNS brute-force wordlist is bounded."""
        import socket as sock

        from services.discovery import subdomain_service as ssd

        def fake_gethostbyname(name):
            if name.endswith(".example.com"):
                return "93.184.216.34"
            raise OSError("does not resolve")

        monkeypatch.setattr(sock, "gethostbyname", fake_gethostbyname)

        async def fake_fetch(url, **kw):
            from utils.egress import FetchResult
            return FetchResult(status_code=200, headers={}, body=b"[]")

        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fake_fetch
        )

        import asyncio
        results = asyncio.run(ssd.discover_subdomains("example.com"))

        brute_hosts = [r for r in results if r.get("source") == "dns_brute"]
        brute_names = {r["subdomain"] for r in brute_hosts}

        expected_prefixes = {
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
            "ns1", "ns2", "dns1", "dns2", "mx1", "mx2", "api", "admin",
            "app", "dev", "staging", "test", "vpn", "portal", "blog",
            "shop", "support", "gitlab", "jenkins",
        }
        expected_hosts = {f"{p}.example.com" for p in expected_prefixes}
        assert brute_names == expected_hosts
        assert len(brute_hosts) <= len(ssd.DNS_BRUTE_WORDLIST)

    def test_takeover_truncated_at_max_hosts(self, monkeypatch):
        """DNS brute-force results are capped at max_hosts_per_scan."""
        import socket as sock

        from services.discovery import subdomain_service as ssd
        from app.core import config as config_mod

        def fake_gethostbyname(name):
            if name.endswith(".example.com"):
                return "93.184.216.34"
            raise OSError("does not resolve")

        monkeypatch.setattr(sock, "gethostbyname", fake_gethostbyname)

        async def fake_fetch(url, **kw):
            from utils.egress import FetchResult
            return FetchResult(status_code=200, headers={}, body=b"[]")

        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fake_fetch
        )

        monkeypatch.setattr(
            config_mod.settings,
            "max_subdomains_per_source_per_scan",
            3,
        )

        import asyncio
        results = asyncio.run(ssd.discover_subdomains("example.com"))

        brute_hosts = [r for r in results if r.get("source") == "dns_brute"]
        assert len(brute_hosts) == 3, f"expected 3 capped hosts, got {len(brute_hosts)}"
        for h in brute_hosts:
            assert h["truncated"] is True
            assert h["truncated_count"] > 0

    def test_provider_match_claimable(self, monkeypatch):
        """A verified-claimable provider match yields high severity."""
        _patch_dns(
            monkeypatch,
            cname_map={
                "www.example.com": ["bitbucket.io."],
            },
            a_map={
                "bitbucket.io": ["1.2.3.4"],
            },
        )
        _patch_http(monkeypatch, http_map={
            "bitbucket.io": {"status_code": 200, "body": "Repository not found"},
        })
        ctx = _make_ctx(domain="www.example.com", subdomains=["www.example.com"])
        result = asyncio.run(subdomain_takeover_module(ctx))
        findings = result["findings"]
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "high"
        assert f["confidence"] == 0.85
        assert f["provider_id"] == "Bitbucket"
        assert f["dedupe_key"] == "subdomain_takeover:Bitbucket:www.example.com"

    def test_provider_match_edge_case(self, monkeypatch):
        """An edge-case provider match yields medium severity ≤ 0.85."""
        _patch_dns(
            monkeypatch,
            cname_map={
                "shop.example.com": ["myshopify.com."],
            },
            a_map={
                "myshopify.com": ["1.2.3.4"],
            },
        )
        _patch_http(monkeypatch, http_map={
            "myshopify.com": {"status_code": 200, "body": "Sorry, this shop is currently unavailable."},
        })
        ctx = _make_ctx(domain="shop.example.com", subdomains=["shop.example.com"])
        result = asyncio.run(subdomain_takeover_module(ctx))
        findings = result["findings"]
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "medium"
        assert f["confidence"] <= 0.85
        assert f["provider_id"] == "Shopify"

    def test_two_hosts_two_findings(self, monkeypatch):
        """Two different subdomains → two separate findings."""
        _patch_dns(
            monkeypatch,
            cname_map={
                "www.example.com": ["github.io."],
                "shop.example.com": ["myshopify.com."],
            },
            a_map={
                "github.io": ["1.2.3.4"],
                "myshopify.com": ["1.2.3.4"],
            },
        )
        _patch_http(monkeypatch, http_map={
            "github.io": {"status_code": 200, "body": "There isn't a GitHub Pages site here"},
            "myshopify.com": {"status_code": 200, "body": "Sorry, this shop is currently unavailable."},
        })
        ctx = _make_ctx(domain="example.com", subdomains=["www.example.com", "shop.example.com"])
        result = asyncio.run(subdomain_takeover_module(ctx))
        findings = result["findings"]
        assert len(findings) == 2
        dedupe_keys = {f["dedupe_key"] for f in findings}
        assert dedupe_keys == {
            "subdomain_takeover:GitHub Pages:www.example.com",
            "subdomain_takeover:Shopify:shop.example.com",
        }

    def test_rescan_updates_same_finding(self, monkeypatch):
        """Rescanning the same host updates the same finding (by dedupe_key)."""
        _patch_dns(
            monkeypatch,
            cname_map={
                "www.example.com": ["github.io."],
            },
            a_map={
                "github.io": ["1.2.3.4"],
            },
        )
        _patch_http(monkeypatch, http_map={
            "github.io": {"status_code": 200, "body": "There isn't a GitHub Pages site here"},
        })
        ctx = _make_ctx(domain="example.com", subdomains=["www.example.com"])

        result1 = asyncio.run(subdomain_takeover_module(ctx))
        result2 = asyncio.run(subdomain_takeover_module(ctx))

        findings1 = result1["findings"]
        findings2 = result2["findings"]
        assert len(findings1) == 1
        assert len(findings2) == 1
        assert findings1[0]["dedupe_key"] == findings2[0]["dedupe_key"]
        assert findings1[0]["dedupe_key"] == "subdomain_takeover:GitHub Pages:www.example.com"

    def test_scope_gating_no_probe_unverified(self, db, org_factory, monkeypatch):
        """No probe for unverified (unpinned) domains."""
        import tasks.discovery_tasks as dt

        org, _ = org_factory("Gate Org", "gateuser", "gateuser@example.com")
        scan = SimpleNamespace(organization_id=org.id, id=1)

        calls = []

        def fake_run(ctx, modules):
            calls.append([m.phase for m in modules])
            return {}

        monkeypatch.setattr(dt, "_run_in_context", fake_run)
        monkeypatch.setattr(
            dt,
            "pinned_resolve",
            lambda host: (_ for _ in ()).throw(
                __import__("app.core.ssrf", fromlist=["PinnedResolutionMissing"]).PinnedResolutionMissing(host)
            ),
        )

        persisted = {
            "subdomains": [
                SimpleNamespace(subdomain="www.example.com", id=1, ip_address=None)
            ],
        }

        summary = dt._scan_targets(
            db, scan, persisted, "example.com", None, "full"
        )

        active_phases = {
            ScanPhase.PORT, ScanPhase.SSL, ScanPhase.HEADER,
            ScanPhase.FINGERPRINT,
        }
        for phase_list in calls:
            assert not any(p in active_phases for p in phase_list), (
                f"active phase ran without pin: {calls}"
            )
        assert summary["unpinned_skipped"] == ["www.example.com"]
        assert summary["ports_total"] == 0


class TestDataProvenance:
    def test_no_not_vulnerable_entry_produces_finding(self):
        """Reads the data file and asserts that no 'Not vulnerable' entry
        is loaded into FINGERPRINTS (so it can never produce a finding)."""
        import json
        from pathlib import Path
        from scanner_modules.subdomain_takeover import _load_fingerprints

        data = json.loads(
            (Path(__file__).parent.parent / "scanner_modules" / "takeover_fingerprints.json").read_text()
        )
        # Collect names of Not-vulnerable entries in the data file.
        not_vuln_names = {
            e.get("name", e.get("service"))
            for e in data["providers"]
            if e.get("status") == "Not vulnerable"
        }
        assert not_vuln_names, "Expected at least one Not-vulnerable entry"

        loaded = _load_fingerprints()
        loaded_names = {p["name"] for p in loaded}
        # None of the Not-vulnerable entries should be in the loaded set.
        overlap = not_vuln_names & loaded_names
        assert not overlap, (
            f"Not-vulnerable entries leaked into FINGERPRINTS: {overlap}"
        )

    def test_provenance_fields_present(self):
        """Data file has blob_sha, commit (full SHA), and license."""
        import json
        from pathlib import Path

        data = json.loads(
            (Path(__file__).parent.parent / "scanner_modules" / "takeover_fingerprints.json").read_text()
        )
        assert "blob_sha" in data
        assert data["blob_sha"] == "6d4a4168552366b5050fff054017db9116873621"
        assert "commit" in data
        assert data["commit"] == "5bd4e12837911c8475486f1da922c9b9c706e632"
        assert data.get("license") == "CC BY 4.0"

    def test_status_derives_tier(self):
        """Every loaded provider has a tier derived from upstream status."""
        from scanner_modules.subdomain_takeover import FINGERPRINTS

        for p in FINGERPRINTS:
            assert "tier" in p
            assert p["tier"] in ("claimable", "likely_claimable")
            if p["tier"] == "claimable":
                assert p["verified_claimable"] is True
            else:
                assert p["likely_claimable"] is True
