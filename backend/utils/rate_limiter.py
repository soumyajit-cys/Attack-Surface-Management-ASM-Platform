from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
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

# Disable slowapi's in-memory fallback so a dead Redis backend never silently
# turns fail-open.  Storage errors propagate and are caught by
# _FailClosedMiddleware, which answers 429.
limiter._in_memory_fallback = False
limiter._swallow_errors = False


class _FailClosedMiddleware(BaseHTTPMiddleware):
    """If the rate-limit backend (Redis) is down and ``rate_limit_fail_closed``
    is set, reject every non-health request with 429 instead of letting traffic
    through (fail-open).  Two detection paths:

    1. ``limiter._storage_dead`` is already True (slowapi flagged the backend
       dead on a previous request) -- answer 429 immediately.
    2. A Redis/storage exception propagates out of ``call_next`` (first request
       after an outage) -- catch it and answer 429.

    Health checks are always exempt.
    """

    def __init__(self, app, fail_closed: bool = True) -> None:
        super().__init__(app)
        self.fail_closed = fail_closed

    # Paths that must never be rate-limited or blocked by a storage failure.
    _EXEMPT_PATHS = frozenset({"/health", "/metrics", "/"})

    async def dispatch(self, request: Request, call_next):
        if not self.fail_closed:
            return await call_next(request)
        if request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)
        # Fast path: backend already known dead.
        if getattr(limiter, "_storage_dead", False):
            logger.warning(
                "Rate-limit backend dead; failing closed for %s",
                request.url.path,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "message": "Rate limit service unavailable",
                        "code": "rate_limit_storage_down",
                    }
                },
            )
        try:
            return await call_next(request)
        except Exception as exc:  # noqa: BLE001
            from redis.exceptions import RedisError

            if isinstance(exc, RedisError) or "redis" in type(exc).__module__:
                logger.warning(
                    "Rate-limit backend unreachable; failing closed for %s",
                    request.url.path,
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "message": "Rate limit service unavailable",
                            "code": "rate_limit_storage_down",
                        }
                    },
                )
            raise


def setup_rate_limiting(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # Enforces default_limits (60/min) on routes WITHOUT their own decorator.
    app.add_middleware(SlowAPIMiddleware)
    # Fail-closed wrapper (outermost): catches Redis/storage errors from
    # slowapi -- both middleware-driven and decorator-driven limits -- and
    # answers 429 instead of failing open or 500.
    app.add_middleware(
        _FailClosedMiddleware, fail_closed=settings.rate_limit_fail_closed
    )
    logger.info(
        "Rate limiting configured with storage: %s (fail_closed=%s)",
        redact_redis_url(settings.redis_url),
        settings.rate_limit_fail_closed,
    )
