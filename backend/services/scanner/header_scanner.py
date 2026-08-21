import asyncio
import httpx

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
    if not url.startswith("http"):
        url = f"https://{url}"

    findings = []

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            verify=True,
        ) as client:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, info in SECURITY_HEADERS.items():
                if header.lower() not in headers:
                    findings.append({
                        "title": f"Missing {info['name']} Header",
                        "severity": info["severity"],
                        "category": "security_headers",
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                    })

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

    except httpx.SSLError:
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url.replace("https://", "http://"))
                headers = {k.lower(): v for k, v in resp.headers.items()}
                for header, info in SECURITY_HEADERS.items():
                    if header.lower() not in headers:
                        findings.append({
                            "title": f"Missing {info['name']} Header (HTTP)",
                            "severity": info["severity"],
                            "category": "security_headers",
                            "description": info["description"],
                            "recommendation": info["recommendation"],
                        })
        except Exception as exc:
            logger.warning("Header analysis failed for %s: %s", url, exc)

    except Exception as exc:
        logger.warning("Header analysis failed for %s: %s", url, exc)

    return findings