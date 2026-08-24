from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from config import settings
import logging

logger = logging.getLogger("sentinelasm")


def get_client_identifier(request: Request) -> str:
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(
    key_func=get_client_identifier,
    default_limits=[f"{settings.rate_limit_requests_per_minute}/minute"],
    storage_uri=settings.redis_url,
)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    logger.warning("Rate limit exceeded for %s: %s", get_client_identifier(request), exc)
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Rate limit exceeded",
            "retry_after": exc.retry_after,
        },
    )


def setup_rate_limiting(app: FastAPI) -> None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    logger.info("Rate limiting configured with storage: %s", settings.redis_url)