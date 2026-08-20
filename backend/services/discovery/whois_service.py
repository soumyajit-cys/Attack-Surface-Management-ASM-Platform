import whois

from utils.logger import logger


async def get_whois(domain):
    try:
        data = whois.whois(domain)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {
            "registrar": None,
            "creation_date": None,
            "asn": None,
        }

    return {
        "registrar": data.registrar,
        "creation_date": str(data.creation_date),
        "asn": None,
    }