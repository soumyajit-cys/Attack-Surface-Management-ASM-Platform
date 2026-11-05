from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from urllib.parse import urlsplit
from config import settings
import logging
import time

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
# turns fail-open.  Storage errors propagate to our exception handler /
# middleware, which answers 429 on sensitive endpoints only.
limiter._in_memory_fallback = False
limiter._swallow_errors = False

# Sensitive endpoints where a Redis outage must fail closed (never let an
# unauthenticated or state-changing request slip through unmetered).
_SENSITIVE_PATH_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/scans",
    "/api/v1/enrichment/providers",
)

# How often (seconds) to probe whether Redis is back after an outage.
_BACKEND_CHECK_INTERVAL = 5.0
_last_backend_check: float = 0.0


def _is_sensitive_path(path: str) -> bool:
    return any(path.startswith(p) for p in _SENSITIVE_PATH_PREFIXES)


def _redis_down_handler(request: Request, exc: Exception) -> JSONResponse:
    """429 when the rate-limit backend (Redis) is unreachable on a sensitive
    endpoint.  Marks the backend dead so subsequent sensitive requests fail
    closed until Redis recovers.  Non-sensitive endpoints are NOT affected."""
    limiter._storage_dead = True
    logger.warning(
        "Rate-limit backend unreachable (%s); failing closed for %s",
        type(exc).__name__,
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


class _FailClosedMiddleware(BaseHTTPMiddleware):
    """Fail-closed for sensitive endpoints only when Redis is down.

    Two detection paths:
    1. ``limiter._storage_dead`` is already True -- answer 429 immediately
       for sensitive paths.
    2. A Redis/storage exception reaches this middleware -- catch it and
       answer 429 for sensitive paths.

    Health checks and normal reads are never blocked by a storage failure:
    they proceed unmetered (fail-open) so a Redis blip cannot take down
    /health, /metrics, or read-only endpoints.
    """

    def __init__(self, app, fail_closed: bool = True) -> None:
        super().__init__(app)
        self.fail_closed = fail_closed

    _EXEMPT_PATHS = frozenset({"/health", "/metrics", "/"})

    async def dispatch(self, request: Request, call_next):
        if not self.fail_closed:
            return await call_next(request)
        if request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)
        # Fast path: backend already known dead -- sensitive paths only.
        if getattr(limiter, "_storage_dead", False) and _is_sensitive_path(
            request.url.path
        ):
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
                limiter._storage_dead = True
                if _is_sensitive_path(request.url.path):
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
                # Non-sensitive path: log and proceed unmetered (fail-open).
                logger.warning(
                    "Rate-limit backend unreachable; failing open for %s",
                    request.url.path,
                )
            raise


def reset_storage_dead() -> None:
    """Test helper: clear the _storage_dead flag so tests start fresh."""
    limiter._storage_dead = False


def setup_rate_limiting(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # Fail-closed: when Redis is unreachable, slowapi's middleware catches the
    # storage error and falls back to the registered exception handler.  Our
    # RedisError handler answers 429 on sensitive endpoints only.
    from redis.exceptions import RedisError

    app.add_exception_handler(RedisError, _redis_down_handler)
    # Enforces default_limits (60/min) on routes WITHOUT their own decorator.
    app.add_middleware(SlowAPIMiddleware)
    # Fail-closed wrapper (outermost): catches Redis/storage errors that
    # propagate through and answers 429 on sensitive endpoints.
    app.add_middleware(
        _FailClosedMiddleware, fail_closed=settings.rate_limit_fail_closed
    )
    logger.info(
        "Rate limiting configured with storage: %s (fail_closed=%s)",
        redact_redis_url(settings.redis_url),
        settings.rate_limit_fail_closed,
    )
