from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from urllib.parse import urlsplit
from config import settings
import logging

logger = logging.getLogger("sentinelasm")


def redact_redis_url(url: str) -> str:
    """Host-only form of a Redis URL for logs (drops credentials/query)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "redis://unknown"
    if not parts.hostname:
        return "redis://unknown"
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or ""
    scheme = parts.scheme or "redis"
    return f"{scheme}://{parts.hostname}{port}{path}"


def get_client_identifier(request: Request) -> str:
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(
    key_func=get_client_identifier,
    default_limits=[f"{settings.rate_limit_requests_per_minute}/minute"],
    storage_uri=settings.redis_url,
)


def setup_rate_limiting(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    logger.info("Rate limiting configured with storage: %s", redact_redis_url(settings.redis_url))