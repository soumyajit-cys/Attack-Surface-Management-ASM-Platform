"""SSRF guard: validates scan targets and blocks private/metadata IPs.

Chunk 2 additions:
- ``_strip_mapped_prefix`` strips ``::ffff:x.x.x.x`` → ``x.x.x.x`` so
  IPv4-mapped IPv6 addresses are caught by the private-IP check.
- ``normalize_ip`` is a public helper that callers can use before comparison.
"""

import ipaddress
import re
from typing import Optional

from utils.logger import logger


PRIVATE_IP_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("fc00::/7"),
]

CLOUD_METADATA_IPS = [
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "169.254.169.253",
    "fd00:ec2::254",
]

# Explicitly non-routable networks (Phase 1, task 1.3). Checked with the
# ``ipaddress`` module -- never with hostname string matching. Deliberately
# exhaustive rather than relying on version-dependent ``is_global`` flags.
_NON_ROUTABLE_V4 = [
    ipaddress.IPv4Network("0.0.0.0/8"),        # unspecified / software scope
    ipaddress.IPv4Network("10.0.0.0/8"),       # private
    ipaddress.IPv4Network("100.64.0.0/10"),    # CGNAT shared space
    ipaddress.IPv4Network("127.0.0.0/8"),      # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local (+ cloud metadata)
    ipaddress.IPv4Network("172.16.0.0/12"),    # private
    ipaddress.IPv4Network("192.168.0.0/16"),   # private
    ipaddress.IPv4Network("224.0.0.0/4"),      # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # reserved (+ broadcast)
]

_NON_ROUTABLE_V6 = [
    ipaddress.IPv6Network("::/128"),           # unspecified
    ipaddress.IPv6Network("::1/128"),          # loopback
    ipaddress.IPv6Network("fe80::/10"),        # link-local
    ipaddress.IPv6Network("fc00::/7"),         # unique-local
    ipaddress.IPv6Network("ff00::/8"),         # multicast
]

# Transition mechanisms that embed an IPv4 address: the embedded address
# must itself be globally routable.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_SIXTO4_NET = ipaddress.IPv6Network("2002::/16")


def normalize_ip(ip_str: str) -> str:
    """Normalize an IP string: strip IPv4-mapped prefix, return canonical form.

    ``::ffff:127.0.0.1`` → ``127.0.0.1``
    ``::1``              → ``::1``
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
    except ValueError:
        pass
    return ip_str


def is_private_ip(ip: str) -> bool:
    canonical = normalize_ip(ip)
    try:
        ip_obj = ipaddress.ip_address(canonical)
        for network in PRIVATE_IP_RANGES:
            if ip_obj in network:
                return True
        # Catch-all: any IPv6 link-local or ULA that slipped through.
        if ip_obj.is_link_local or ip_obj.is_loopback:
            return True
        return False
    except ValueError:
        return False


def is_cloud_metadata_ip(ip: str) -> bool:
    canonical = normalize_ip(ip)
    return canonical in CLOUD_METADATA_IPS


def _parse_ipv4_flexible(text: str):
    """Parse dotted IPv4 in decimal, octal, hex, or short form (inet_aton).

    Returns an ``IPv4Address`` or ``None``. Rejects empty parts, out-of-range
    values, and non-numeric junk. ``%`` zone ids never reach here (rejected
    by the caller).
    """
    parts = text.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums: list[int] = []
    for part in parts:
        if not part:
            return None
        try:
            if len(part) > 2 and part[:2] in ("0x", "0X"):
                value = int(part, 16)
            elif len(part) > 1 and part[0] == "0" and part.isdigit():
                value = int(part, 8)
            elif part.isdigit():
                value = int(part, 10)
            else:
                return None
        except ValueError:
            return None
        nums.append(value)
    if len(nums) == 1:
        (value,) = nums
        if not 0 <= value <= 0xFFFFFFFF:
            return None
    elif len(nums) == 2:
        a, b = nums
        if a > 255 or b > 0xFFFFFF:
            return None
        value = (a << 24) | b
    elif len(nums) == 3:
        a, b, c = nums
        if a > 255 or b > 255 or c > 0xFFFF:
            return None
        value = (a << 24) | (b << 16) | c
    else:
        if any(n > 255 for n in nums):
            return None
        value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def _embedded_ipv4(addr: ipaddress.IPv6Address):
    """Unwrap transition-mechanism addresses to their embedded IPv4, if any."""
    if addr.ipv4_mapped:
        return addr.ipv4_mapped
    if addr in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if addr in _SIXTO4_NET:
        return ipaddress.IPv4Address((int(addr) >> 80) & 0xFFFFFFFF)
    return None


def is_globally_routable_ip(ip: str) -> bool:
    """The ONE shared egress check (Phase 1, task 1.3).

    True only when *ip* is a globally routable unicast address: anything
    private, loopback, link-local, CGNAT, multicast, reserved, unspecified,
    broadcast, or cloud-metadata -- including IPv4-mapped IPv6, NAT64/6to4
    embeddings of blocked IPv4, non-standard IPv4 encodings, IPv6 zone ids,
    and unparseable input -- returns False. Takes IP literals only; hostnames
    must be resolved with ``getaddrinfo`` first, never string-matched.
    """
    if not isinstance(ip, str):
        return False
    text = ip.strip()
    if not text or "%" in text:
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        parsed = _parse_ipv4_flexible(text)
        if parsed is None:
            return False
        addr = parsed

    candidates = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            candidates.append(embedded)

    for candidate in candidates:
        if isinstance(candidate, ipaddress.IPv4Address):
            if any(candidate in net for net in _NON_ROUTABLE_V4):
                return False
        else:
            if any(candidate in net for net in _NON_ROUTABLE_V6):
                return False
        if str(candidate) in CLOUD_METADATA_IPS or candidate.compressed in CLOUD_METADATA_IPS:
            return False
    return True


def is_allowed_target(ip: str) -> bool:
    # Now defined as the shared globally-routable check (strict superset of
    # the old private/metadata behavior). Kept for existing callers.
    return is_globally_routable_ip(ip)


def validate_scan_target(domain: str, resolved_ip: Optional[str] = None) -> tuple[bool, str]:
    if not domain:
        return False, "Empty domain"

    if resolved_ip:
        if not is_allowed_target(resolved_ip):
            return False, f"Target IP {resolved_ip} is not allowed (private/cloud metadata)"

    return True, "OK"


async def verify_domain_ownership(domain: str, challenge_token: str) -> tuple[bool, str]:
    import dns.resolver
    import dns.exception

    txt_name = f"_sentinelasm-challenge.{domain}"
    expected_value = f"sentinelasm-verification={challenge_token}"

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        answers = resolver.resolve(txt_name, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode() == expected_value:
                    return True, "Domain ownership verified"

        return False, f"TXT record not found or doesn't match expected value: {expected_value}"

    except dns.resolver.NXDOMAIN:
        return False, f"Domain {domain} does not exist"
    except dns.resolver.NoAnswer:
        return False, f"No TXT record found at {txt_name}"
    except dns.exception.Timeout:
        return False, "DNS query timed out"
    except Exception as exc:
        logger.warning("Domain ownership verification failed for %s: %s", domain, exc)
        return False, f"Verification error: {str(exc)}"


def generate_ownership_challenge(domain: str) -> tuple[str, str]:
    import secrets
    token = secrets.token_urlsafe(16)
    txt_name = f"_sentinelasm-challenge.{domain}"
    expected_value = f"sentinelasm-verification={token}"
    return token, expected_value
