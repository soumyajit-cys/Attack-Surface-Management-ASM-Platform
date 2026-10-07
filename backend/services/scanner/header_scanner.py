from utils.egress import EgressBlocked, fetch_url_validated
from utils.logger import logger

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS",
        "severity": "high",
        "description": "HTTP Strict Transport Security not set",
        "recommendation": "Add Strict-Transport-Security header with max-age >= 31536000",
    },
    "Content-Security-Policy": {
        "name": "CSP",
        "severity": "medium",
        "description": "Content Security Policy not set",
        "recommendation": "Implement a restrictive Content-Security-Policy header",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "X-Frame-Options not set",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "description": "X-Content-Type-Options not set",
        "recommendation": "Add X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Referrer-Policy not set",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Permissions-Policy not set",
        "recommendation": "Add Permissions-Policy to restrict browser features",
    },
    "Cross-Origin-Opener-Policy": {
        "name": "COOP",
        "severity": "low",
        "description": "Cross-Origin-Opener-Policy not set",
        "recommendation": "Add Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "name": "CORP",
        "severity": "low",
        "description": "Cross-Origin-Resource-Policy not set",
        "recommendation": "Add Cross-Origin-Resource-Policy: same-origin",
    },
}

INSECURE_HEADERS = {
    "Server": "Server header discloses version information",
    "X-Powered-By": "X-Powered-By header discloses technology stack",
    "X-AspNet-Version": "X-AspNet-Version header discloses framework version",
    "X-AspNetMvc-Version": "X-AspNetMvc-Version header discloses framework version",
}


async def analyze_headers(url: str) -> list[dict]:
    """Fetch through the validated egress helper (no client-side redirects).

    Blocked destinations raise ``EgressBlocked``; other failures return [].
    A failed TLS fetch retries once over plain HTTP through the same
    validated path -- never with verification disabled.
    """
    if not url.startswith("http"):
        url = f"https://{url}"

    try:
        result = await fetch_url_validated(url, timeout=15.0)
        return _headers_to_findings(result.headers, http_fallback=False)
    except EgressBlocked:
        raise
    except Exception:
        if not url.startswith("https://"):
            logger.warning("Header analysis failed for %s", url)
            return []
        try:
            http_url = "http://" + url[len("https://"):]
            result = await fetch_url_validated(http_url, timeout=15.0)
            return _headers_to_findings(result.headers, http_fallback=True)
        except EgressBlocked:
            raise
        except Exception as exc:
            logger.warning("Header analysis failed for %s: %s", url, exc)
            return []


def _headers_to_findings(headers: dict, http_fallback: bool) -> list[dict]:
    suffix = " (HTTP)" if http_fallback else ""
    headers = {k.lower(): v for k, v in headers.items()}

    findings = []
    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append({
                "title": f"Missing {info['name']} Header{suffix}",
                "severity": info["severity"],
                "category": "security_headers",
                "description": info["description"],
                "recommendation": info["recommendation"],
            })

    if http_fallback:
        return findings

    for header, desc in INSECURE_HEADERS.items():
        if header.lower() in headers:
            findings.append({
                "title": f"Information Disclosure: {header} Header",
                "severity": "low",
                "category": "security_headers",
                "description": f"{desc}: {headers[header.lower()]}",
                "recommendation": f"Remove or obfuscate the {header} header",
            })

    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age" in hsts.lower():
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0].split(",")[0])
            if max_age < 31536000:
                findings.append({
                    "title": "HSTS Max-Age Too Low",
                    "severity": "medium",
                    "category": "security_headers",
                    "description": f"HSTS max-age is {max_age} seconds (recommended >= 31536000)",
                    "recommendation": "Set HSTS max-age to at least 31536000 (1 year)",
                })
        except Exception:
            pass

    return findings
