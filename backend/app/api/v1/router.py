"""Aggregates all v1 routers under ``/api/v1``."""

from fastapi import APIRouter

from app.api.v1 import (
    alerting,
    auth,
    dashboard,
    findings,
    organizations,
    reports,
    scan_policies,
    scans,
)

api_v1_router = APIRouter()
api_v1_router.include_router(auth.router, prefix="/v1")
api_v1_router.include_router(scans.router, prefix="/v1")
api_v1_router.include_router(findings.router, prefix="/v1")
api_v1_router.include_router(dashboard.router, prefix="/v1")
api_v1_router.include_router(organizations.router, prefix="/v1")
api_v1_router.include_router(alerting.router, prefix="/v1")
api_v1_router.include_router(reports.router, prefix="/v1")
api_v1_router.include_router(scan_policies.router, prefix="/v1")