import asyncio
import traceback

from sqlalchemy.orm import Session

from metrics.prometheus import SCAN_COUNTER
from models.asset import Asset
from models.finding import Finding
from models.risk_score import RiskScore
from models.scan_history import ScanHistory
from services.discovery.domain_service import resolve_domain
from services.discovery.dns_service import enumerate_dns
from services.discovery.subdomain_service import discover_subdomains
from services.discovery.whois_service import get_whois
from services.findings.finding_engine import generate_findings
from services.scanner.header_scanner import analyze_headers
from services.scanner.persistence import (
    persist_discovery_results,
    persist_port_results,
    persist_ssl_result,
)
from services.scanner.port_scanner import scan_ports
from services.scanner.ssl_scanner import analyze_ssl
from services.scoring.risk_engine import calculate_risk
from utils.database import SessionLocal
from utils.logger import logger
from workers.celery_app import celery

MAX_PORT_SUBDOMAINS = 5


def _ssl_risk_level(ssl_data: dict | None) -> str:
    if not ssl_data:
        return "unknown"
    if ssl_data.get("self_signed"):
        return "high"
    if ssl_data.get("expired"):
        return "critical"
    if ssl_data.get("expires_soon"):
        return "high"
    return "low"


@celery.task(bind=True, name="tasks.run_discovery")
def run_discovery(self, scan_id: int):
    SCAN_COUNTER.inc()

    db: Session = SessionLocal()
    try:
        scan = db.query(ScanHistory).filter(
            ScanHistory.id == scan_id
        ).first()
        if scan is None:
            logger.error("ScanHistory %s not found", scan_id)
            return {"scan_id": scan_id, "status": "not_found"}

        scan.status = "running"
        scan.error = None
        db.commit()

        domain_name = scan.target

        results = asyncio.run(_collect(domain_name))

        resolved_ip = results["resolved"].get("ip")

        subdomain_names = results["subdomains"]
        if domain_name not in subdomain_names:
            subdomain_names.insert(0, domain_name)

        normalized = []
        for name in subdomain_names:
            name = name.strip().lower().rstrip(".")
            if not name or "*" in name:
                continue
            if name.endswith(domain_name):
                normalized.append({
                    "subdomain": name,
                    "source": "crt.sh" if name != domain_name else "primary",
                })

        persisted = persist_discovery_results(
            db,
            scan.organization_id,
            domain_name,
            {
                "dns": results["dns"],
                "registrar": results["whois"].get("registrar"),
                "asn": results["whois"].get("asn"),
                "subdomains": normalized,
            },
        )
        db.commit()

        scan_summary = _scan_targets(
            db,
            scan,
            persisted,
            domain_name,
            resolved_ip,
        )
        db.commit()

        asset_id = persisted["asset_id"]
        _generate_and_persist_findings(
            db,
            scan,
            asset_id,
            scan_summary,
        )
        _persist_risk_score(db, scan, asset_id, scan_summary)
        db.commit()

        scan.status = "completed"
        scan.completed_at = _now()
        db.commit()

        logger.info(
            "Scan %s completed for %s: %s",
            scan_id,
            domain_name,
            scan_summary,
        )
        return {"scan_id": scan_id, "status": "completed"}

    except Exception as exc:
        db.rollback()
        scan = db.query(ScanHistory).filter(
            ScanHistory.id == scan_id
        ).first()
        if scan is not None:
            scan.status = "failed"
            scan.error = str(exc)
            scan.completed_at = _now()
            db.commit()
        logger.error(
            "Scan %s failed: %s\n%s",
            scan_id,
            exc,
            traceback.format_exc(),
        )
        raise
    finally:
        db.close()


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


async def _collect(domain_name: str) -> dict:
    resolved, dns, subdomains, whois = await asyncio.gather(
        resolve_domain(domain_name),
        enumerate_dns(domain_name),
        discover_subdomains(domain_name),
        get_whois(domain_name),
    )
    return {
        "resolved": resolved,
        "dns": dns,
        "subdomains": subdomains,
        "whois": whois,
    }


def _scan_targets(
    db: Session,
    scan: ScanHistory,
    persisted: dict,
    domain_name: str,
    resolved_ip: str | None,
) -> dict:
    from models.subdomain import Subdomain

    targets = persisted["subdomains"]
    summary = {
        "ports_open": 0,
        "ports_total": 0,
        "open_port_numbers": [],
        "ssl": {"scanned": 0, "issues": 0},
        "headers": {"scanned": 0, "issues": 0},
    }

    for sub in targets[:MAX_PORT_SUBDOMAINS]:
        host = sub.subdomain
        try:
            ports = asyncio.run(scan_ports(host))
        except Exception:
            continue

        open_ports = [p for p in ports if p.get("status") == "open"]
        summary["ports_total"] += len(ports)
        summary["ports_open"] += len(open_ports)
        summary["open_port_numbers"].extend(
            p["port"] for p in open_ports
        )
        persist_port_results(db, sub, ports)

        try:
            ssl_data = asyncio.run(analyze_ssl(host))
            ssl_data["risk_level"] = _ssl_risk_level(ssl_data)
            persist_ssl_result(db, sub, ssl_data)
            summary["ssl"]["scanned"] += 1
            if ssl_data["risk_level"] in ("high", "critical"):
                summary["ssl"]["issues"] += 1
        except Exception:
            pass

        try:
            header_issues = asyncio.run(
                analyze_headers(f"https://{host}")
            )
            summary["headers"]["scanned"] += 1
            summary["headers"]["issues"] += len(header_issues)
            _persist_header_issues(db, scan, sub, header_issues)
        except Exception:
            pass

    return summary


def _persist_header_issues(
    db: Session,
    scan: ScanHistory,
    sub,
    issues: list,
) -> None:
    from models.finding import Finding

    for issue in issues:
        title = f"{sub.subdomain}: {issue}"
        existing = (
            db.query(Finding)
            .filter(
                Finding.organization_id == scan.organization_id,
                Finding.title == title,
                Finding.asset_id == sub.domain.asset_id,
            )
            .first()
        )
        if existing is None:
            db.add(Finding(
                organization_id=scan.organization_id,
                asset_id=sub.domain.asset_id,
                title=title,
                severity="medium",
                category="security_headers",
                description=issue,
                recommendation=(
                    "Configure the missing security header in the "
                    "web server or CDN configuration."
                ),
            ))


def _generate_and_persist_findings(
    db: Session,
    scan: ScanHistory,
    asset_id: int,
    summary: dict,
) -> None:
    if summary["ssl"]["issues"]:
        db.add(Finding(
            organization_id=scan.organization_id,
            asset_id=asset_id,
            title="Weak or expiring TLS certificates detected",
            severity="high",
            category="tls",
            description=(
                f"{summary['ssl']['issues']} target(s) have "
                "self-signed, expiring or expired certificates."
            ),
            recommendation="Renew certificates and remove self-signed certs.",
        ))

    findings = generate_findings(
        open_ports=[
            {"port": p, "status": "open"}
            for p in summary["open_port_numbers"]
        ],
        ssl_risk="low",
        header_findings=[],
    )

    for finding in findings:
        db.add(Finding(
            organization_id=scan.organization_id,
            asset_id=asset_id,
            title=finding["title"],
            severity=finding["severity"],
            category=finding.get("category", "general"),
            description=finding.get("description"),
            recommendation=finding.get("recommendation"),
        ))


def _persist_risk_score(
    db: Session,
    scan: ScanHistory,
    asset_id: int,
    summary: dict,
) -> None:
    severity = 1.0
    if summary["ssl"]["issues"]:
        severity = 3.0

    exposure = 1.0
    if summary["ports_open"] > 5:
        exposure = 1.5

    score = calculate_risk(
        exposure=exposure,
        severity=severity,
        confidence=0.8,
    )

    existing = (
        db.query(RiskScore)
        .filter(RiskScore.asset_id == asset_id)
        .first()
    )
    if existing is None:
        db.add(RiskScore(
            asset_id=asset_id,
            score=score,
            exposure=exposure,
            severity=severity,
            confidence=0.8,
        ))
    else:
        existing.score = score
        existing.exposure = exposure
        existing.severity = severity