import csv
import io
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.orm import Session

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
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        writer.writerow([
            f.id,
            asset.name if asset else "Unknown",
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
    assets = db.query(Asset).filter(
        Asset.organization_id == organization_id,
    ).all()

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
        domains = db.query(Domain).filter(Domain.asset_id == asset.id).all()
        subdomain_count = sum(len(d.subdomains) for d in domains)

        open_ports = 0
        for domain in domains:
            for sub in domain.subdomains:
                open_ports += db.query(Port).filter(
                    Port.subdomain_id == sub.id,
                    Port.status == "open",
                ).count()

        findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        risk_score = db.query(RiskScore).filter(RiskScore.asset_id == asset.id).first()

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