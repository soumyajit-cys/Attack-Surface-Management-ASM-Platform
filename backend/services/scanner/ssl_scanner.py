import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import Optional

from utils.logger import logger


async def analyze_ssl(host: str) -> Optional[dict]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(
            None,
            lambda: socket.create_connection((host, 443), timeout=10)
        )

        ssl_sock = await loop.run_in_executor(
            None,
            lambda: context.wrap_socket(sock, server_hostname=host)
        )

        cert = ssl_sock.getpeercert(binary_form=False)
        cert_der = ssl_sock.getpeercert(binary_form=True)
        tls_version = ssl_sock.version()
        cipher = ssl_sock.cipher()

        ssl_sock.close()
        sock.close()

        if not cert:
            return None

        return _parse_cert(host, cert, cert_der, tls_version, cipher)

    except ssl.SSLCertVerificationError as exc:
        return await _analyze_ssl_unverified(host, str(exc))
    except Exception as exc:
        logger.warning("SSL analysis failed for %s: %s", host, exc)
        return None


async def _analyze_ssl_unverified(host: str, error: str) -> Optional[dict]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(
            None,
            lambda: socket.create_connection((host, 443), timeout=10)
        )

        ssl_sock = await loop.run_in_executor(
            None,
            lambda: context.wrap_socket(sock, server_hostname=host)
        )

        cert = ssl_sock.getpeercert(binary_form=False)
        cert_der = ssl_sock.getpeercert(binary_form=True)
        tls_version = ssl_sock.version()
        cipher = ssl_sock.cipher()

        ssl_sock.close()
        sock.close()

        if not cert:
            return None

        result = _parse_cert(host, cert, cert_der, tls_version, cipher)
        result["verify_error"] = error
        return result

    except Exception as exc:
        logger.warning("SSL analysis (unverified) failed for %s: %s", host, exc)
        return None


def _parse_cert(host: str, cert: dict, cert_der: bytes, tls_version: str, cipher: tuple) -> dict:
    issuer = _format_name(cert.get("issuer", []))
    subject = _format_name(cert.get("subject", []))

    not_after = cert.get("notAfter")
    expires_at = None
    expired = False
    expires_soon = False
    if not_after:
        try:
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            expired = expires_at < now
            expires_soon = (expires_at - now).days <= 30
        except Exception:
            pass

    san = []
    for ext in cert.get("subjectAltName", []):
        if ext[0] == "DNS":
            san.append(ext[1])

    self_signed = issuer == subject

    chain_length = 1

    return {
        "host": host,
        "issuer": issuer,
        "subject": subject,
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
        "cipher_version": cipher[1] if cipher and len(cipher) > 1 else None,
        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
        "expires_at": expires_at,
        "expired": expired,
        "expires_soon": expires_soon,
        "self_signed": self_signed,
        "san": san,
        "chain_length": chain_length,
        "risk_level": _calculate_risk_level(expired, expires_soon, self_signed, tls_version),
    }


def _format_name(name: list) -> str:
    parts = []
    for rdn in name:
        for attr in rdn:
            parts.append(f"{attr[0]}={attr[1]}")
    return ", ".join(parts)


def _calculate_risk_level(expired: bool, expires_soon: bool, self_signed: bool, tls_version: str) -> str:
    if expired or self_signed:
        return "critical"
    if expires_soon:
        return "high"
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        return "high"
    return "low"