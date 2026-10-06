from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.api.v1.router import api_v1_router
from app.core.config import settings, validate_runtime_config
from app.core.errors import register_error_handlers
from utils.rate_limiter import setup_rate_limiting
from metrics.middleware import PrometheusMiddleware

# Fail fast on invalid configuration (weak/missing JWT secret, prod misuse).
validate_runtime_config()

app = FastAPI(
    title="SentinelASM",
    description=(
        "Attack Surface Management platform: discovery, scanning, "
        "finding synthesis, risk scoring and alerting."
    ),
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_rate_limiting(app)

app.add_middleware(PrometheusMiddleware)

register_error_handlers(app)

# Versioned API only (legacy unversioned surface removed in Phase 0 task 0.4;
// invitation accept, org create, and digest test were ported to /api/v1).
app.include_router(api_v1_router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
