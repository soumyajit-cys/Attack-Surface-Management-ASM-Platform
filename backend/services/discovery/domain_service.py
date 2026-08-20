import socket

from utils.logger import logger


async def resolve_domain(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip": ip}
    except Exception as exc:
        logger.warning("DNS resolution failed for %s: %s", domain, exc)
        return {"domain": domain, "ip": None}