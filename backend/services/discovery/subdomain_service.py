import requests

from utils.logger import logger

CRT_API = "https://crt.sh/?q=%25.{}&output=json"


async def discover_subdomains(domain):
    try:
        response = requests.get(
            CRT_API.format(domain),
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.warning(
            "crt.sh discovery failed for %s: %s",
            domain,
            exc,
        )
        return []

    subdomains = set()

    for item in data:
        name = item.get("name_value")
        if name:
            for entry in name.split("\n"):
                entry = entry.strip().lower().rstrip(".")
                if entry and "*" not in entry:
                    subdomains.add(entry)

    return list(subdomains)