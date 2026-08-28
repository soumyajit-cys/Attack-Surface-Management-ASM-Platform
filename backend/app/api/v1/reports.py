"""``/api/v1/reports`` -- CSV + PDF report exports."""

from datetime import datetime
from io import BytesIO
from typing import Optional

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.errors import AppError, NotFoundError
from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db
from models.finding import Finding
from services.reporting.csv_export import (
    export_all_csv,
    export_assets_csv,
    export_domains_csv,
    export_findings_csv,
    export_scans_csv,
)
from services.reporting.pdf_report import (
    generate_executive_summary,
    generate_finding_detail_pdf,
)

router = APIRouter(prefix="/reports", tags=["reports"])

_REPORT_DEP = require_permissions_dep(Permission.REPORT_EXPORT)


class CSVExportRequest(BaseModel):
    asset_id: Optional[int] = None
    since: Optional[datetime] = None
    severity: Optional[str] = None


def _attachment(name: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{name}_{datetime.now().strftime("%Y%m%d")}"'}


@router.post("/export/findings/csv")
async def export_findings_csv_endpoint(
    data: CSVExportRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_REPORT_DEP),
):
    csv_content = export_findings_csv(
        db,
        principal.organization_id,
        asset_id=data.asset_id,
        since=data.since,
        severity=data.severity,
    )
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="findings_{datetime.now().strftime("%Y%m%d")}.csv"'
        },
    )


@router.post("/export/assets/csv")
async def export_assets_csv_endpoint(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_REPORT_DEP),
):
    csv_content = export_assets_csv(db, principal.organization_id)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="assets_{datetime.now().strftime("%Y%m%d")}.csv"'
        },
    )


@router.post("/export/scans/csv")
async def export_scans_csv_endpoint(
    data: CSVExportRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_REPORT_DEP),
):
    csv_content = export_scans_csv(
        db,
        principal.organization_id,
        since=data.since,
    )
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="scans_{datetime.now().strftime("%Y%m%d")}.csv"'
        },
    )


@router.post("/export/domains/csv")
async def export_domains_csv_endpoint(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_REPORT_DEP),
):
    csv_content = export_domains_csv(db, principal.organization_id)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="domains_{datetime.now().strftime("%Y%m%d")}.csv"'
        },
    )


@router.post("/export/all/csv")
async def export_all_csv_endpoint(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_REPORT_DEP),
):
    csv_files = export_all_csv(db, principal.organization_id)

    import zipfile
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in csv_files.items():
            zf.writestr(filename, content)

    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="sentinelasm_export_{datetime.now().strftime("%Y%m%d")}.zip"'
        },
    )


@router.get("/pdf/executive-summary")
async def executive_summary_pdf(
    asset_id: Optional[int] = None,
    since: Optional[datetime] = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_REPORT_DEP),
):
    try:
        pdf_bytes = generate_executive_summary(
            db,
            principal.organization_id,
            asset_id=asset_id,
            since=since,
        )
    except RuntimeError as exc:
        raise AppError(str(exc), code="pdf_unavailable")
    except Exception as exc:
        raise AppError(
            f"Failed to generate PDF: {exc}",
            code="pdf_generation_failed",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="executive_summary_{datetime.now().strftime("%Y%m%d")}.pdf"'
        },
    )


@router.get("/pdf/finding/{finding_id}")
async def finding_detail_pdf(
    finding_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_REPORT_DEP),
):
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.organization_id == principal.organization_id,
    ).first()
    if not finding:
        raise NotFoundError("Finding not found", code="finding_not_found")

    try:
        pdf_bytes = generate_finding_detail_pdf(db, finding_id)
    except RuntimeError as exc:
        raise AppError(str(exc), code="pdf_unavailable")
    except Exception as exc:
        raise AppError(
            f"Failed to generate PDF: {exc}",
            code="pdf_generation_failed",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="finding_{finding_id}_{datetime.now().strftime("%Y%m%d")}.pdf"'
        },
    )