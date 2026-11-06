from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import _find_route_handler
from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match
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
# turns fail-open.
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
    closed until Redis recovers (probed periodically by the middleware).
    Non-sensitive endpoints are NOT affected."""
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


def _probe_backend() -> bool:
    """Quickly check whether Redis is back. Returns True if reachable."""
    try:
        limiter._storage.check()
        return True
    except Exception:  # noqa: BLE001
        return False


def _find_handler(routes, scope):
    """Find the route endpoint function for *scope* (mirrors slowapi's
    internal helper so per-route ``@limiter.limit`` decorators still work
    without SlowAPIMiddleware)."""
    handler = None
    for route in routes:
        match, _ = route.matches(scope)
        if match == Match.FULL and hasattr(route, "endpoint"):
            handler = route.endpoint
    return handler


class _FailClosedMiddleware(BaseHTTPMiddleware):
    """Fail-closed for sensitive endpoints only when Redis is down.

    Rate limiting is checked manually in this middleware (SlowAPIMiddleware is
    not used, so Redis/storage errors propagate cleanly to our except block
    instead of being swallowed by SlowAPI's internal exception handler).

    1. Before ``call_next``, check the default rate limit and any per-route
       limit (from ``@limiter.limit`` decorators) manually.
    2. If Redis is down: sensitive endpoints get 429 (fail-closed);
       non-sensitive endpoints proceed unmetered (fail-open).
    3. If limit exceeded (Redis up): return 429 normally.
    4. Periodically probe Redis for recovery.

    Health checks and normal reads are never blocked by a storage failure.
    """

    def __init__(self, app, fail_closed: bool = True) -> None:
        super().__init__(app)
        self.fail_closed = fail_closed

    _NO_LIMIT_PATHS = frozenset({"/health", "/"})
    # Rate-limited but never blocked by a Redis storage failure.
    _FAIL_CLOSED_EXEMPT_PATHS = frozenset({"/metrics"})

    async def dispatch(self, request: Request, call_next):
        global _last_backend_check
        if not self.fail_closed:
            return await call_next(request)
        if request.url.path in self._NO_LIMIT_PATHS:
            return await call_next(request)
        sensitive = _is_sensitive_path(request.url.path)

        # Fast path: backend already known dead -- probe before deciding.
        if getattr(limiter, "_storage_dead", False):
            now = time.monotonic()
            if now - _last_backend_check >= _BACKEND_CHECK_INTERVAL:
                _last_backend_check = now
                if _probe_backend():
                    limiter._storage_dead = False
                    logger.info("Rate-limit backend recovered")
            if sensitive:
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
            # Non-sensitive (including /metrics): proceed unmetered
            # (fail-open) when Redis is down.
            return await call_next(request)

        # Check rate limits manually (default limits).  Per-route
        # @limiter.limit decorators are enforced by the decorator wrapper
        # inside the endpoint itself.
        handler = _find_handler(request.app.routes, request.scope)
        try:
            limiter._check_request_limit(request, handler, True)
        except RateLimitExceeded as exc:
            return _rate_limit_exceeded_handler(request, exc)
        except Exception as exc:  # noqa: BLE001
            from redis.exceptions import RedisError

            if isinstance(exc, RedisError) or "redis" in type(exc).__module__:
                limiter._storage_dead = True
                _last_backend_check = time.monotonic()
                if sensitive:
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
                # Non-sensitive path (including /metrics): log and proceed
                # unmetered (fail-open) when Redis is down.
                logger.warning(
                    "Rate-limit backend unreachable; failing open for %s",
                    request.url.path,
                )
                return await call_next(request)
            raise

        response = await call_next(request)
        return response


def reset_storage_dead() -> None:
    """Test helper: clear the _storage_dead flag so tests start fresh."""
    limiter._storage_dead = False


def setup_rate_limiting(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # No SlowAPIMiddleware: rate limiting is handled manually by
    # _FailClosedMiddleware so Redis/storage errors propagate to our except
    # block instead of being swallowed by SlowAPI's internal handler.
    app.add_middleware(
        _FailClosedMiddleware, fail_closed=settings.rate_limit_fail_closed
    )
    logger.info(
        "Rate limiting configured with storage: %s (fail_closed=%s)",
        redact_redis_url(settings.redis_url),
        settings.rate_limit_fail_closed,
    )
