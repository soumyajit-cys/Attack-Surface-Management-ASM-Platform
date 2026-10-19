import csv
import io
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.orm import Session, joinedload, selectinload

from models import Finding, Asset, Organization, ScanHistory, Domain, Subdomain, Port, SSLResult, RiskScore


def export_findings_csv(
    db: Session,
    organization_id: int,
    asset_id: Optional[int] = None,
    since: Optional[datetime] = None,
    severity: Optional[str] = None,
) -> str:
    query = db.query(Finding).join(Asset).filter(
        Finding.organization_id == organization_id,
    )

    if asset_id:
        query = query.filter(Finding.asset_id == asset_id)

    if since:
        query = query.filter(Finding.created_at >= since)

    if severity:
        query = query.filter(Finding.severity == severity)

    findings = query.order_by(Finding.created_at.desc()).all()

    # Batch the asset-name lookup (was one SELECT per finding).
    asset_ids = {f.asset_id for f in findings if f.asset_id is not None}
    asset_names: dict[int, str] = {}
    if asset_ids:
        asset_names = {
            a.id: a.name
            for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
        }

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Finding ID",
        "Asset Name",
        "Asset ID",
        "Title",
        "Severity",
        "Category",
        "Description",
        "Recommendation",
        "Created At",
    ])

    for f in findings:
        writer.writerow([
            f.id,
            asset_names.get(f.asset_id, "Unknown"),
            f.asset_id,
            f.title,
            f.severity,
            f.category or "",
            f.description or "",
            f.recommendation or "",
            f.created_at.isoformat() if f.created_at else "",
        ])

    return output.getvalue()


def export_assets_csv(
    db: Session,
    organization_id: int,
) -> str:
    from sqlalchemy import func

    assets = db.query(Asset).filter(
        Asset.organization_id == organization_id,
    ).all()

    # Batch every per-asset/per-subdomain lookup into five grouped queries
    # (was: per-asset Domain/Finding/RiskScore SELECTs plus one Port.count()
    # SELECT per subdomain).
    asset_ids = [a.id for a in assets]

    domains_by_asset: dict[int, list[Domain]] = {}
    domain_subdomain_counts: dict[int, int] = {}
    open_ports_by_asset: dict[int, int] = {}
    severity_by_asset: dict[tuple[int, str], int] = {}
    risk_by_asset: dict[int, RiskScore] = {}

    if asset_ids:
        for domain in (
            db.query(Domain).filter(Domain.asset_id.in_(asset_ids)).all()
        ):
            domains_by_asset.setdefault(domain.asset_id, []).append(domain)

        subdomain_counts = (
            db.query(Subdomain.domain_id, func.count(Subdomain.id))
            .join(Domain, Domain.id == Subdomain.domain_id)
            .filter(Domain.asset_id.in_(asset_ids))
            .group_by(Subdomain.domain_id)
            .all()
        )
        domain_subdomain_counts = dict(subdomain_counts)

        open_ports = (
            db.query(Domain.asset_id, func.count(Port.id))
            .join(Subdomain, Subdomain.domain_id == Domain.id)
            .join(Port, Port.subdomain_id == Subdomain.id)
            .filter(Domain.asset_id.in_(asset_ids), Port.status == "open")
            .group_by(Domain.asset_id)
            .all()
        )
        open_ports_by_asset = dict(open_ports)

        severity_counts = (
            db.query(Finding.asset_id, Finding.severity, func.count(Finding.id))
            .filter(Finding.asset_id.in_(asset_ids))
            .group_by(Finding.asset_id, Finding.severity)
            .all()
        )
        severity_by_asset = {(aid, sev): c for aid, sev, c in severity_counts}

        risk_by_asset = {
            r.asset_id: r
            for r in db.query(RiskScore).filter(
                RiskScore.asset_id.in_(asset_ids)).all()
        }

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Asset ID",
        "Name",
        "Criticality",
        "Domain Count",
        "Subdomain Count",
        "Open Port Count",
        "Finding Count (Critical)",
        "Finding Count (High)",
        "Finding Count (Medium)",
        "Finding Count (Low)",
        "Risk Score",
        "Created At",
    ])

    for asset in assets:
        domains = domains_by_asset.get(asset.id, [])
        subdomain_count = sum(
            domain_subdomain_counts.get(d.id, 0) for d in domains
        )
        open_ports = open_ports_by_asset.get(asset.id, 0)

        critical = severity_by_asset.get((asset.id, "critical"), 0)
        high = severity_by_asset.get((asset.id, "high"), 0)
        medium = severity_by_asset.get((asset.id, "medium"), 0)
        low = severity_by_asset.get((asset.id, "low"), 0)

        risk_score = risk_by_asset.get(asset.id)

        writer.writerow([
            asset.id,
            asset.name,
            asset.criticality,
            len(domains),
            subdomain_count,
            open_ports,
            critical,
            high,
            medium,
            low,
            risk_score.score if risk_score else "",
            asset.created_at.isoformat() if asset.created_at else "",
        ])

    return output.getvalue()


def export_scans_csv(
    db: Session,
    organization_id: int,
    since: Optional[datetime] = None,
) -> str:
    query = db.query(ScanHistory).filter(
        ScanHistory.organization_id == organization_id,
    )

    if since:
        query = query.filter(ScanHistory.started_at >= since)

    scans = query.order_by(ScanHistory.started_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Scan ID",
        "Target",
        "Status",
        "Error",
        "Started At",
        "Completed At",
        "Duration (seconds)",
    ])

    for scan in scans:
        duration = None
        if scan.completed_at and scan.started_at:
            duration = int((scan.completed_at - scan.started_at).total_seconds())

        writer.writerow([
            scan.id,
            scan.target,
            scan.status,
            scan.error or "",
            scan.started_at.isoformat() if scan.started_at else "",
            scan.completed_at.isoformat() if scan.completed_at else "",
            duration if duration else "",
        ])

    return output.getvalue()


def export_domains_csv(
    db: Session,
    organization_id: int,
) -> str:
    domains = db.query(Domain).join(Asset).filter(
        Asset.organization_id == organization_id,
    ).options(
        # One joined load for the asset name + two selectin loads replace
        # three lazy SELECTs per domain below.
        joinedload(Domain.asset),
        selectinload(Domain.subdomains),
        selectinload(Domain.dns_records),
    ).all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Domain ID",
        "Asset Name",
        "Domain",
        "Registrar",
        "ASN",
        "Hosting Provider",
        "Subdomain Count",
        "DNS Record Count",
        "Created At",
    ])

    for domain in domains:
        subdomain_count = len(domain.subdomains)
        dns_count = len(domain.dns_records)

        writer.writerow([
            domain.id,
            domain.asset.name if domain.asset else "Unknown",
            domain.domain,
            domain.registrar or "",
            domain.asn or "",
            domain.hosting_provider or "",
            subdomain_count,
            dns_count,
            domain.created_at.isoformat() if domain.created_at else "",
        ])

    return output.getvalue()


def export_all_csv(
    db: Session,
    organization_id: int,
) -> dict[str, str]:
    return {
        "findings.csv": export_findings_csv(db, organization_id),
        "assets.csv": export_assets_csv(db, organization_id),
        "scans.csv": export_scans_csv(db, organization_id),
        "domains.csv": export_domains_csv(db, organization_id),
    }