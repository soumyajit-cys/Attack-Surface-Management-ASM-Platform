from datetime import datetime, timezone


def assess_ssl_risk(ssl_data: dict) -> dict:
    if not ssl_data:
        return {
            "risk_level": "unknown",
            "findings": [],
            "score": 0.0,
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
        })
        risk_score += 10.0

    if ssl_data.get("self_signed"):
        findings.append({
            "title": "Self-Signed SSL Certificate",
            "severity": "high",
            "category": "tls",
            "description": "The certificate is self-signed and not trusted by browsers.",
            "recommendation": "Replace with a certificate from a trusted CA.",
        })
        risk_score += 8.0

    if ssl_data.get("expires_soon"):
        findings.append({
            "title": "SSL Certificate Expiring Soon",
            "severity": "high",
            "category": "tls",
            "description": f"Certificate expires on {ssl_data.get('expires_at')} (within 30 days)",
            "recommendation": "Renew the SSL certificate before expiration.",
        })
        risk_score += 6.0

    tls_version = ssl_data.get("tls_version", "")
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append({
            "title": f"Deprecated TLS Version: {tls_version}",
            "severity": "high",
            "category": "tls",
            "description": f"Server supports deprecated TLS version {tls_version}",
            "recommendation": "Disable TLS 1.0 and 1.1; enable TLS 1.2 and 1.3 only.",
        })
        risk_score += 7.0

    cipher = ssl_data.get("cipher", "")
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
    if any(wc in cipher.upper() for wc in weak_ciphers):
        findings.append({
            "title": "Weak Cipher Suite",
            "severity": "medium",
            "category": "tls",
            "description": f"Server supports weak cipher: {cipher}",
            "recommendation": "Disable weak cipher suites; prefer AES-GCM or ChaCha20-Poly1305.",
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
    }