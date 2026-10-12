from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
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
    # Single source (utils.client_ip): X-Forwarded-For is honored only behind
    # TRUSTED_PROXIES, so spoofing the header cannot rotate the limiter key.
    # Falls back to the direct peer; "unknown" only if even that is missing.
    from utils.client_ip import get_client_ip

    return get_client_ip(request) or "unknown"


limiter = Limiter(
    key_func=get_client_identifier,
    default_limits=[f"{settings.rate_limit_requests_per_minute}/minute"],
    storage_uri=settings.redis_url,
)


def setup_rate_limiting(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # Enforces default_limits (60/min) on routes WITHOUT their own decorator.
    # Decorated routes are skipped here (slowapi._should_exempt defers to the
    # decorator), so their exact limits are unchanged -- no double counting.
    app.add_middleware(SlowAPIMiddleware)
    logger.info("Rate limiting configured with storage: %s", redact_redis_url(settings.redis_url))