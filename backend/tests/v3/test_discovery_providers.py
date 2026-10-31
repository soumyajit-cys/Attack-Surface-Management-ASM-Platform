"""Discovery provider tests (Phase 2).

Fixtures only, no real network.  Covers hostname normalization, out-of-scope
filtering, wildcard handling, crt.sh (mocked egress), caching, rate limiting,
failure/timeout paths, and the FakeProvider.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from services.discovery.providers.base import (
    DiscoveryProvider,
    DiscoveredHost,
    ProviderResult,
    normalize_host,
)
from services.discovery.providers.crt_sh import CrtShProvider, _TOKEN_BUCKET_LUA
from services.discovery.providers.fake import FakeProvider
from utils.redis_client import get_redis


# ── normalization ──────────────────────────────────────────────────────────


class TestNormalizeHost:
    def test_lowercases_and_strips_trailing_dot(self):
        assert normalize_host("WWW.Example.COM.") == "www.example.com"

    def test_strips_wildcard_prefix(self):
        # The wildcard marker is removed from the host itself.
        assert normalize_host("*.example.com") == "example.com"

    def test_punycode(self):
        assert normalize_host("münchen.example.com") == "xn--mnchen-3ya.example.com"

    def test_rejects_invalid(self):
        assert normalize_host("") is None
        assert normalize_host("   ") is None
        assert normalize_host("not-a-domain") is None  # no dot
        assert normalize_host("-bad.example.com") is None  # label starts with hyphen
        assert normalize_host("bad-.example.com") is None  # label ends with hyphen
        assert normalize_host("a" * 64 + ".example.com") is None  # label too long
        assert normalize_host(" " * 300) is None


# ── DiscoveryProvider protocol ────────────────────────────────────────────


class _StubProvider(DiscoveryProvider):
    name = "stub"
    requires_key = False

    def __init__(self, result: ProviderResult):
        self._result = result

    async def lookup(self, domain: str) -> ProviderResult:  # type: ignore[override]
        return self._result


class TestProviderProtocol:
    def test_protocol_attributes(self):
        result = ProviderResult(
            provider="stub", hosts=[DiscoveredHost(host="x.example.com", source="stub")]
        )
        p = _StubProvider(result)
        assert p.name == "stub"
        assert p.requires_key is False
        assert asyncio.iscoroutinefunction(p.lookup)


# ── crt.sh provider (mocked egress) ───────────────────────────────────────


class FakeFetch:
    """Scripted fetch_url_validated replacement."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs.get("timeout"), kwargs.get("max_bytes")))
        if not self._responses:
            raise RuntimeError("no more scripted responses")
        return self._responses.pop(0)


class _FetchResult:
    def __init__(self, status_code, body=b""):
        self.status_code = status_code
        self.body = body


class TestCrtShProvider:
    @pytest.fixture()
    def provider(self):
        return CrtShProvider(
            rate_limit_per_min=1000,  # effectively unlimited
            cache_ttl_seconds=60,
            timeout_seconds=5.0,
            max_retries=1,
            max_bytes=524288,
        )

    def _domain_row(self):
        # crt.sh name_value uses newline-separated names; a wildcard cert uses
        # "*.example.com\nwww.example.com".
        return [
            {"name_value": "www.example.com\nmail.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "unrelated.com"},  # out of scope
            {"name_value": "not-a-domain"},  # invalid
            {"name_value": ""},  # empty
        ]

    @pytest.mark.asyncio
    async def test_lookup_returns_in_scope_hosts_and_dedups(self, provider, monkeypatch):
        fetch = FakeFetch([_FetchResult(200, b'[{"name_value":"www.example.com\nwww.example.com"}]')])
        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fetch
        )
        result = await provider.lookup("example.com")
        assert result.error is None
        assert result.cache_hit is False
        hosts = {h.host for h in result.hosts}
        assert hosts == {"www.example.com"}
        # crt.sh is queried exactly once.
        assert len(fetch.calls) == 1

    @pytest.mark.asyncio
    async def test_wildcard_recorded_without_literal_host(self, provider, monkeypatch):
        body = '[{"name_value":"*.example.com\nwww.example.com"}]'
        fetch = FakeFetch([_FetchResult(200, body.encode())])
        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fetch
        )
        result = await provider.lookup("example.com")
        assert result.error is None
        hosts = {h.host for h in result.hosts}
        assert "www.example.com" in hosts
        assert "*.example.com" not in hosts  # no literal wildcard host
        assert any(h.is_wildcard for h in result.hosts if h.host == "example.com")

    @pytest.mark.asyncio
    async def test_out_of_scope_and_invalid_dropped(self, provider, monkeypatch):
        body = (
            '[{"name_value":"www.example.com"},'
            '{"name_value":"unrelated.com"},'
            '{"name_value":"bad-host"},'
            '{"name_value":""}]'
        )
        fetch = FakeFetch([_FetchResult(200, body.encode())])
        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fetch
        )
        result = await provider.lookup("example.com")
        assert result.error is None
        assert {h.host for h in result.hosts} == {"www.example.com"}

    @pytest.mark.asyncio
    async def test_cache_hit_skips_fetch(self, provider, monkeypatch):
        fetch = FakeFetch([_FetchResult(200, b'[{"name_value":"cached.example.com"}]')])
        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fetch
        )
        # First call populates the cache.
        await provider.lookup("example.com")
        assert len(fetch.calls) == 1
        # Second call hits the cache.
        result = await provider.lookup("example.com")
        assert len(fetch.calls) == 1  # no additional fetch
        assert result.cache_hit is True
        assert {h.host for h in result.hosts} == {"cached.example.com"}

    @pytest.mark.asyncio
    async def test_503_retries_then_succeeds(self, provider, monkeypatch):
        fetch = FakeFetch(
            [
                _FetchResult(503),
                _FetchResult(200, b'[{"name_value":"retry.example.com"}]'),
            ]
        )
        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fetch
        )
        result = await provider.lookup("example.com")
        assert result.error is None
        assert {h.host for h in result.hosts} == {"retry.example.com"}
        assert len(fetch.calls) == 2

    @pytest.mark.asyncio
    async def test_exhausted_retries_record_error(self, provider, monkeypatch):
        fetch = FakeFetch([_FetchResult(503), _FetchResult(503)])
        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", fetch
        )
        result = await provider.lookup("example.com")
        assert result.error is not None
        assert result.hosts == []
        assert result.hosts_returned == 0

    @pytest.mark.asyncio
    async def test_egress_blocked_fail_closed_no_retry(self, provider, monkeypatch):
        from utils.egress import EgressBlocked

        async def blocked(*a, **k):
            raise EgressBlocked("blocked address")

        monkeypatch.setattr(
            "services.discovery.providers.crt_sh.fetch_url_validated", blocked
        )
        result = await provider.lookup("example.com")
        assert result.error is not None
        assert "egress_blocked" in result.error
        # fetch attempted once (fail closed, no retry).
        assert result.hosts == []

    @pytest.mark.asyncio
    async def test_empty_domain(self, provider):
        result = await provider.lookup("")
        assert result.error == "empty domain"
        assert result.hosts == []


class TestCrtShRateLimit:
    def test_token_bucket_grants_and_depletes(self):
        r = get_redis()
        r.flushdb()
        key = "ratelimit:test:bucket"
        rate_per_sec = 1.0
        max_burst = 2
        granted = []
        for _ in range(4):
            granted.append(
                bool(
                    r.eval(
                        _TOKEN_BUCKET_LUA,
                        1,
                        key,
                        rate_per_sec,
                        max_burst,
                        __import__("time").time(),
                    )
                )
            )
        assert granted == [True, True, False, False], granted
        r.delete(key)


# ── FakeProvider ───────────────────────────────────────────────────────────


class TestFakeProvider:
    @pytest.mark.asyncio
    async def test_returns_configured_hosts(self):
        p = FakeProvider(hosts=["a.example.com", "b.example.com"])
        result = await p.lookup("example.com")
        assert result.error is None
        assert {h.host for h in result.hosts} == {"a.example.com", "b.example.com"}
        assert p.lookup_count == 1

    @pytest.mark.asyncio
    async def test_error_is_non_fatal(self):
        p = FakeProvider(error="boom")
        result = await p.lookup("example.com")
        assert result.error == "boom"
        assert result.hosts == []
