import requests


HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy"
]


async def analyze_headers(url):

    response = requests.get(
        url,
        timeout=10
    )

    findings = []

    for header in HEADERS:

        if header not in response.headers:

            findings.append(
                f"Missing {header}"
            )

    return findings


