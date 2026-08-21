import asyncio
import concurrent.futures
import traceback

from sqlalchemy.orm import Session

from metrics.prometheus import SCAN_COUNTER
from models.finding import Finding
from models.risk_score import RiskScore
from models.scan_history import ScanHistory
from services.discovery.domain_service import resolve_domain
from services.discovery.dns_service import enumerate_dns
from services.discovery.subdomain_service import (
    discover_subdomains,
    resolve_subdomain_ips,
)
from services.discovery.whois_service import get_whois
from services.findings.finding_engine import generate_findings
from services.history.change_detector import (
    create_asset_snapshot,
    detect_changes,
    persist_alerts,
)
from services.scanner.header_scanner import analyze_headers
from services.scanner.persistence import (
    persist_discovery_results,
    persist_port_results,
    persist_ssl_result,
    persist_subdomain_ips,
)
from services.scanner.port_scanner import scan_ports
from services.scanner.ssl_scanner import analyze_ssl
from services.scanner.ssl_risk import assess_ssl_risk
from services.scoring.risk_engine import calculate_risk
from utils.database import SessionLocal
from utils.logger import logger
from workers.celery_app import celery

MAX_PORT_SUBDOMAINS = 5


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

        results = _run_async(lambda: _collect(domain_name))

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

        for sub in persisted["subdomains"]:
            ips = _run_async(lambda: resolve_subdomain_ips(sub.subdomain))
            if ips:
                persist_subdomain_ips(db, sub, ips)
                sub.ip_address = ips[0]
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

        create_asset_snapshot(db, asset_id)
        changes = detect_changes(db, asset_id)
        if changes:
            persist_alerts(db, changes, scan.organization_id)

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


def _run_async(coro_factory):
    """Run a coroutine on its own event loop.

    Works inside an already-running event loop (e.g. eager Celery execution
    during a FastAPI request in tests) as well as in a plain worker process.
    """
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=1,
    ) as pool:
        return pool.submit(
            asyncio.run,
            coro_factory(),
        ).result()


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
        "ssl_findings": [],
        "header_findings": [],
    }

    for sub in targets[:MAX_PORT_SUBDOMAINS]:
        host = sub.subdomain
        try:
            ports = _run_async(lambda: scan_ports(host))
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
            ssl_data = _run_async(lambda: analyze_ssl(host))
            ssl_assessment = assess_ssl_risk(ssl_data)
            persist_ssl_result(db, sub, ssl_data)
            summary["ssl"]["scanned"] += 1
            if ssl_assessment["risk_level"] in ("high", "critical"):
                summary["ssl"]["issues"] += 1
            for finding in ssl_assessment["findings"]:
                summary["ssl_findings"].append(finding)
        except Exception:
            pass

        try:
            header_issues = _run_async(
                lambda: analyze_headers(f"https://{host}")
            )
            summary["headers"]["scanned"] += 1
            summary["headers"]["issues"] += len(header_issues)
            for issue in header_issues:
                summary["header_findings"].append(issue)
        except Exception:
            pass

    return summary


def _generate_and_persist_findings(
    db: Session,
    scan: ScanHistory,
    asset_id: int,
    summary: dict,
) -> None:
    findings = generate_findings(
        open_ports=[
            {"port": p, "status": "open"}
            for p in summary["open_port_numbers"]
        ],
        ssl_findings=summary.get("ssl_findings", []),
        header_findings=summary.get("header_findings", []),
    )

    for finding in findings:
        existing = (
            db.query(Finding)
            .filter(
                Finding.organization_id == scan.organization_id,
                Finding.asset_id == asset_id,
                Finding.title == finding["title"],
            )
            .first()
        )
        if existing is not None:
            continue
        db.add(Finding(
            organization_id=scan.organization_id,
            asset_id=asset_id,
            title=finding["title"],
            severity=finding["severity"],
            category=finding.get("category", "general"),
            description=finding.get("description"),
            recommendation=finding.get("recommendation"),
        ))

    db.flush()


def _persist_risk_score(
    db: Session,
    scan: ScanHistory,
    asset_id: int,
    summary: dict,
) -> None:
    from services.scoring.risk_engine import recalculate_asset_risk_score
    recalculate_asset_risk_score(db, asset_id)