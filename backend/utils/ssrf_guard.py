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
]


def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in PRIVATE_IP_RANGES:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return False


def is_cloud_metadata_ip(ip: str) -> bool:
    return ip in CLOUD_METADATA_IPS


def is_allowed_target(ip: str) -> bool:
    if is_private_ip(ip):
        return False
    if is_cloud_metadata_ip(ip):
        return False
    return True


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