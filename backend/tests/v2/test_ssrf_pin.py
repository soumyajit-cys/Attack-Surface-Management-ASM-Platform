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
)


class TestValidateAndPin:
    def test_public_ip_pins(self, monkeypatch):
        monkeypatch.setattr("socket.gethostbyname", lambda host: "93.184.216.34")
        assert validate_and_pin("pinned.example.com") == "93.184.216.34"
        assert pinned_resolve("pinned.example.com") == "93.184.216.34"
        clear_pin("pinned.example.com")

    def test_blocked_ip_rejected(self, monkeypatch):
        monkeypatch.setattr("socket.gethostbyname", lambda host: "127.0.0.1")
        with pytest.raises(ValueError, match="globally routable"):
            validate_and_pin("evil.example.com")

    def test_unresolvable_rejected(self, monkeypatch):
        import socket as stdlib_socket

        def _raise(host):
            raise stdlib_socket.gaierror("nope")

        monkeypatch.setattr("socket.gethostbyname", _raise)
        with pytest.raises(ValueError, match="resolution failed"):
            validate_and_pin("missing.invalid")


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
