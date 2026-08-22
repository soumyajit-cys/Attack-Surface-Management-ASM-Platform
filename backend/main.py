from fastapi import FastAPI

from api.routes.auth import router as auth_router
from api.routes.scans import router as scan_router
from api.routes.findings import router as findings_router
from api.routes.dashboard import router as dashboard_router
from api.routes.organizations import router as organizations_router
from api.routes.scan_policies import router as scan_policies_router
from api.routes.graph import router as graph_router
from api.routes.alerting import router as alerting_router

app = FastAPI(
    title="SentinelASM",
    description=(
        "Attack Surface Management platform: discovery, scanning, "
        "finding synthesis, risk scoring and alerting."
    ),
    version="0.1.0",
)

app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(dashboard_router)
app.include_router(organizations_router)
app.include_router(scan_policies_router)
app.include_router(graph_router)
app.include_router(alerting_router)


@app.get("/health")
async def health():
    return {"status": "ok"}