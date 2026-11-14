from datetime import datetime, timezone
import math

# Compute once: can the container test legacy protocols?
try:
    import ssl as _ssl
    _ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    _ctx.minimum_version = _ssl.TLSVersion.TLSv1
    _ctx.set_ciphers("ALL:@SECLEVEL=0")
    LEGACY_PROTOCOLS_TESTABLE = True
except Exception:
    LEGACY_PROTOCOLS_TESTABLE = False


def assess_ssl_risk(ssl_data: dict) -> dict:
    if not ssl_data:
        return {
            "risk_level": "unknown",
            "findings": [],
            "score": 0.0,
            "legacy_protocols_testable": LEGACY_PROTOCOLS_TESTABLE,
        }

    findings = []
    risk_score = 0.0

    if ssl_data.get("expired"):
        findings.append({
            "title": "SSL Certificate Expired",
            "severity": "critical",
            "category": "tls",
            "description": f"Certificate expired on {ssl_data.get('expires_at')}",
            "recommendation": "Renew the SSL certificate immediately.",
            "dedupe_key": f"ssl_expired:{ssl_data.get('host', '')}",
        })
        risk_score += 10.0

    if ssl_data.get("self_signed"):
        findings.append({
            "title": "Self-Signed SSL Certificate",
            "severity": "high",
            "category": "tls",
            "description": "The certificate is self-signed and not trusted by browsers.",
            "recommendation": "Replace with a certificate from a trusted CA.",
            "dedupe_key": f"ssl_self_signed:{ssl_data.get('host', '')}",
        })
        risk_score += 8.0

    # Expiry tiers (replace expires_soon; days_remaining = floor in UTC).
    expires_at = ssl_data.get("expires_at")
    if expires_at and not ssl_data.get("expired"):
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        days_remaining = math.floor((expires_at - now).total_seconds() / 86400)
        if days_remaining < 7:
            findings.append({
                "title": "SSL Certificate Expiring Soon (< 7 days)",
                "severity": "high",
                "category": "tls",
                "description": f"Certificate expires in {days_remaining} days ({expires_at})",
                "recommendation": "Renew the SSL certificate immediately.",
                "dedupe_key": f"ssl_expiry_high:{ssl_data.get('host', '')}",
            })
            risk_score += 6.0
        elif days_remaining < 14:
            findings.append({
                "title": "SSL Certificate Expiring Soon (< 14 days)",
                "severity": "medium",
                "category": "tls",
                "description": f"Certificate expires in {days_remaining} days ({expires_at})",
                "recommendation": "Renew the SSL certificate before expiration.",
                "dedupe_key": f"ssl_expiry_medium:{ssl_data.get('host', '')}",
            })
            risk_score += 4.0
        elif days_remaining < 30:
            findings.append({
                "title": "SSL Certificate Expiring Soon (< 30 days)",
                "severity": "low",
                "category": "tls",
                "description": f"Certificate expires in {days_remaining} days ({expires_at})",
                "recommendation": "Plan certificate renewal.",
                "dedupe_key": f"ssl_expiry_low:{ssl_data.get('host', '')}",
            })
            risk_score += 2.0

    # Weak key size / signature algorithm (using cryptography lib).
    cert_der = ssl_data.get("cert_der")
    if cert_der:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
            cert = x509.load_der_x509_certificate(cert_der)
            # Key size check
            pub = cert.public_key()
            key_size = getattr(pub, "key_size", 0)
            if isinstance(pub, rsa.RSAPublicKey) and key_size < 2048:
                findings.append({
                    "title": "Weak RSA Key Size",
                    "severity": "high",
                    "category": "tls",
                    "description": f"RSA key size {key_size} bits (minimum 2048)",
                    "recommendation": "Regenerate certificate with RSA 2048+ or ECDSA P-256+.",
                    "dedupe_key": f"ssl_weak_key:{ssl_data.get('host', '')}",
                })
                risk_score += 7.0
            elif isinstance(pub, ec.EllipticCurvePublicKey) and key_size < 256:
                findings.append({
                    "title": "Weak EC Key Size",
                    "severity": "high",
                    "category": "tls",
                    "description": f"EC key size {key_size} bits (minimum 256)",
                    "recommendation": "Regenerate certificate with ECDSA P-256+.",
                    "dedupe_key": f"ssl_weak_key:{ssl_data.get('host', '')}",
                })
                risk_score += 7.0
            # Signature algorithm check
            sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid)
            if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
                findings.append({
                    "title": "Weak Signature Algorithm",
                    "severity": "high",
                    "category": "tls",
                    "description": f"Certificate uses {sig_alg}",
                    "recommendation": "Regenerate certificate with SHA-256 or better.",
                    "dedupe_key": f"ssl_weak_sig:{ssl_data.get('host', '')}",
                })
                risk_score += 7.0
        except Exception:
            pass

    # Chain problems (from verify codes)
    verify_code = ssl_data.get("verify_code")
    if verify_code == 20:
        findings.append({
            "title": "Incomplete Certificate Chain",
            "severity": "medium",
            "category": "tls",
            "description": "Server did not send intermediate certificates.",
            "recommendation": "Configure the server to send the full certificate chain.",
            "dedupe_key": f"ssl_incomplete_chain:{ssl_data.get('host', '')}",
        })
        risk_score += 4.0
    elif verify_code == 19:
        findings.append({
            "title": "Untrusted Root Certificate",
            "severity": "medium",
            "category": "tls",
            "description": "Certificate chain leads to an untrusted root.",
            "recommendation": "Use a certificate from a publicly trusted CA.",
            "dedupe_key": f"ssl_untrusted_root:{ssl_data.get('host', '')}",
        })
        risk_score += 4.0

    # Minimum TLS version
    tls_version = ssl_data.get("tls_version", "")
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append({
            "title": f"Deprecated TLS Version: {tls_version}",
            "severity": "high",
            "category": "tls",
            "description": f"Server supports deprecated TLS version {tls_version}",
            "recommendation": "Disable TLS 1.0 and 1.1; enable TLS 1.2 and 1.3 only.",
            "dedupe_key": f"ssl_deprecated_tls:{ssl_data.get('host', '')}",
        })
        risk_score += 7.0

    # TLS 1.3 support as info
    if tls_version == "TLSv1.3":
        findings.append({
            "title": "TLS 1.3 Supported",
            "severity": "info",
            "category": "tls",
            "description": "Server supports TLS 1.3.",
            "recommendation": "No action needed.",
            "dedupe_key": f"ssl_tls13:{ssl_data.get('host', '')}",
        })

    cipher = ssl_data.get("cipher", "")
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
    if any(wc in cipher.upper() for wc in weak_ciphers):
        findings.append({
            "title": "Weak Cipher Suite",
            "severity": "medium",
            "category": "tls",
            "description": f"Server supports weak cipher: {cipher}",
            "recommendation": "Disable weak cipher suites; prefer AES-GCM or ChaCha20-Poly1305.",
            "dedupe_key": f"ssl_weak_cipher:{ssl_data.get('host', '')}",
        })
        risk_score += 4.0

    risk_level = "low"
    if risk_score >= 8.0:
        risk_level = "critical"
    elif risk_score >= 5.0:
        risk_level = "high"
    elif risk_score >= 2.0:
        risk_level = "medium"

    return {
        "risk_level": risk_level,
        "findings": findings,
        "score": min(risk_score, 10.0),
        "legacy_protocols_testable": LEGACY_PROTOCOLS_TESTABLE,
    }