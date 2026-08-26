from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from api.routes.auth import router as auth_router
from api.routes.scans import router as scan_router
from api.routes.findings import router as findings_router
from api.routes.dashboard import router as dashboard_router
from api.routes.organizations import router as organizations_router
from api.routes.scan_policies import router as scan_policies_router
from api.routes.graph import router as graph_router
from api.routes.alerting import router as alerting_router
from api.routes.reports import router as reports_router

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

# Legacy surface (migrating incrementally to /api/v1).
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(dashboard_router)
app.include_router(organizations_router)
app.include_router(scan_policies_router)
app.include_router(graph_router)
app.include_router(alerting_router)
app.include_router(reports_router)

# Versioned API.
app.include_router(api_v1_router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
