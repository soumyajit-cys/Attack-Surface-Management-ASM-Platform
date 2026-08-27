"""SSRF pin-and-resolve tests: lifecycle, expiration, rebinding detection."""

import pytest

from app.core.ssrf import (
    PinnedIPMismatch,
    PinnedResolutionMissing,
    assert_pin_consistent,
    clear_pin,
    is_valid_pin,
    pin_ip,
    pinned_resolve,
    validate_and_pin,
    _strip_mapped_prefix,
    _assert_safe_ip,
)


class TestStripMappedPrefix:
    def test_ipv4_mapped_stripped(self):
        assert _strip_mapped_prefix("::ffff:127.0.0.1") == "127.0.0.1"

    def test_ipv4_mapped_10(self):
        assert _strip_mapped_prefix("::ffff:10.0.0.1") == "10.0.0.1"

    def test_regular_ipv4_unchanged(self):
        assert _strip_mapped_prefix("8.8.8.8") == "8.8.8.8"

    def test_ipv6_unchanged(self):
        assert _strip_mapped_prefix("::1") == "::1"

    def test_invalid_string_unchanged(self):
        assert _strip_mapped_prefix("not-an-ip") == "not-an-ip"


class TestAssertSafeIP:
    def test_public_ip_passes(self):
        _assert_safe_ip("8.8.8.8")  # should not raise

    def test_loopback_rejected(self):
        with pytest.raises(ValueError, match="private|loopback"):
            _assert_safe_ip("127.0.0.1")

    def test_private_rejected(self):
        with pytest.raises(ValueError, match="private"):
            _assert_safe_ip("192.168.1.1")

    def test_metadata_rejected(self):
        with pytest.raises(ValueError, match="private|metadata"):
            _assert_safe_ip("169.254.169.254")

    def test_ipv4_mapped_loopback_rejected(self):
        with pytest.raises(ValueError, match="private|loopback"):
            _assert_safe_ip("::ffff:127.0.0.1")

    def test_0_x_rejected(self):
        with pytest.raises(ValueError, match="private|0.0.0.0"):
            _assert_safe_ip("0.0.0.1")


class TestPinLifecycle:
    def test_pin_and_resolve(self):
        pin_ip("test-host.example", "93.184.216.34")
        assert is_valid_pin("test-host.example")
        assert pinned_resolve("test-host.example") == "93.184.216.34"
        clear_pin("test-host.example")
        assert not is_valid_pin("test-host.example")

    def test_missing_pin_raises(self):
        clear_pin("nonexistent.example")
        with pytest.raises(PinnedResolutionMissing):
            pinned_resolve("nonexistent.example")

    def test_clear_pin(self):
        pin_ip("to-clear.example", "93.184.216.34")
        assert is_valid_pin("to-clear.example")
        clear_pin("to-clear.example")
        assert not is_valid_pin("to-clear.example")


class TestAssertPinConsistent:
    def test_missing_pin_raises(self):
        clear_pin("no-pin.example")
        with pytest.raises(PinnedResolutionMissing):
            assert_pin_consistent("no-pin.example")
