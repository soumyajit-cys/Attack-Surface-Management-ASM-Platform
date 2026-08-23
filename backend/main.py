from fastapi import FastAPI
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
from utils.rate_limiter import setup_rate_limiting
from metrics.middleware import PrometheusMiddleware

app = FastAPI(
    title="SentinelASM",
    description=(
        "Attack Surface Management platform: discovery, scanning, "
        "finding synthesis, risk scoring and alerting."
    ),
    version="0.1.0",
)

setup_rate_limiting(app)

app.add_middleware(PrometheusMiddleware)

app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(dashboard_router)
app.include_router(organizations_router)
app.include_router(scan_policies_router)
app.include_router(graph_router)
app.include_router(alerting_router)
app.include_router(reports_router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)