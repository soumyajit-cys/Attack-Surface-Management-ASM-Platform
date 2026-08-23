import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from metrics.prometheus import (
    API_REQUESTS,
    API_REQUEST_DURATION,
)


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()

        response = await call_next(request)

        duration = time.perf_counter() - start_time

        API_REQUESTS.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
        ).inc()

        API_REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path,
        ).observe(duration)

        return response