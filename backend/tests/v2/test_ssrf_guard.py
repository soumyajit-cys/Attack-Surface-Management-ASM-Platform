"""SSRF guard tests: IPv4-mapped IPv6 handling and normalization."""

from utils.ssrf_guard import is_private_ip, is_allowed_target, normalize_ip


class TestNormalizeIP:
    def test_ipv4_mapped_stripped(self):
        assert normalize_ip("::ffff:127.0.0.1") == "127.0.0.1"

    def test_ipv4_mapped_private(self):
        assert normalize_ip("::ffff:192.168.1.1") == "192.168.1.1"

    def test_regular_ipv4_unchanged(self):
        assert normalize_ip("8.8.8.8") == "8.8.8.8"

    def test_ipv6_unchanged(self):
        assert normalize_ip("::1") == "::1"


class TestIPv4MappedDetection:
    def test_mapped_loopback_is_private(self):
        assert is_private_ip("::ffff:127.0.0.1") is True

    def test_mapped_private_is_private(self):
        assert is_private_ip("::ffff:192.168.1.1") is True

    def test_mapped_public_is_allowed(self):
        assert is_private_ip("::ffff:8.8.8.8") is False

    def test_mapped_10_is_private(self):
        assert is_private_ip("::ffff:10.0.0.1") is True

    def test_mapped_metadata_blocked(self):
        assert is_allowed_target("::ffff:169.254.169.254") is False
