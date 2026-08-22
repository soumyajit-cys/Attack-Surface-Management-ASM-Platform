from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from io import BytesIO

from auth.dependencies import get_current_user
from auth.roles import ROLE_ADMIN, require_roles
from models import User
from utils.database import get_db
from services.reporting.csv_export import (
    export_findings_csv,
    export_assets_csv,
    export_scans_csv,
    export_domains_csv,
    export_all_csv,
)
from services.reporting.pdf_report import (
    generate_executive_summary,
    generate_finding_detail_pdf,
)

router = APIRouter(
    prefix="/reports",
    tags=["reports"],
)


class CSVExportRequest(BaseModel):
    asset_id: Optional[int] = None
    since: Optional[datetime] = None
    severity: Optional[str] = None


@router.post("/export/findings/csv")
async def export_findings_csv_endpoint(
    data: CSVExportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    csv_content = export_findings_csv(
        db,
        user.organization_id,
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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    csv_content = export_assets_csv(db, user.organization_id)

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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    csv_content = export_scans_csv(
        db,
        user.organization_id,
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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    csv_content = export_domains_csv(db, user.organization_id)

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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    csv_files = export_all_csv(db, user.organization_id)

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
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    try:
        pdf_bytes = generate_executive_summary(
            db,
            user.organization_id,
            asset_id=asset_id,
            since=since,
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=501,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF: {str(e)}",
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
    user: User = Depends(get_current_user),
):
    from models import Finding

    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.organization_id == user.organization_id,
    ).first()
    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    try:
        pdf_bytes = generate_finding_detail_pdf(db, finding_id)
    except RuntimeError as e:
        raise HTTPException(
            status_code=501,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF: {str(e)}",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="finding_{finding_id}_{datetime.now().strftime("%Y%m%d")}.pdf"'
        },
    )