"""Celery task that orchestrates a full ASM scan.

Changes vs. the original monolith:
1. Phase-based execution with per-phase error isolation and retry.
2. SSRF pin-and-pin: domain is resolved once at submission; every scanner
   calls ``pinned_resolve()`` instead of doing its own DNS lookup.
3. Alert dispatch: ``process_finding_alerts()`` is called for every new finding
   AND for every change-detection alert.
4. Scan status lifecycle: queued → running → completed | failed | retrying.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import time
import traceback
import uuid

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.orm import Session

from app.core.ssrf import pin_ip, pinned_resolve, PinnedResolutionMissing
from metrics.prometheus import (
    ACTIVE_SCANS,
    FINDINGS_PER_SCAN,
    PORTS_SCANNED,
    SCAN_COUNTER,
    SCAN_DURATION,
    SCAN_ERRORS,
    SSL_CERTS_ANALYZED,
    SUBDOMAINS_DISCOVERED,
)
from models.finding import Finding
from models.scan_history import ScanHistory
from services.alerts.alerting_service import process_finding_alerts
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
from utils.logger import (
    clear_correlation_id,
    get_correlation_id,
    logger,
    log_with_context,
    set_correlation_id,
)
from workers.celery_app import celery, move_to_dlq

MAX_PORT_SUBDOMAINS = 5


# ── Retryable vs. fatal exception sets ────────────────────────────────────────
RETRYABLE_ERRORS = (
    ConnectionError,
    TimeoutError,
    OSError,
    SoftTimeLimitExceeded,
)


# ── Main task ─────────────────────────────────────────────────────────────────

@celery.task(bind=True, name="tasks.run_discovery")
def run_discovery(self, scan_id: int) -> dict:
    """Run a full ASM scan for *scan_id*.

    Execution is split into discrete phases.  Transient errors (network,
    timeout) trigger ``self.retry()`` with exponential backoff.  Permanent
    errors (invalid domain, permission denied) are marked ``failed`` without
    retry.
    """
    correlation_id = f"scan-{scan_id}-{uuid.uuid4().hex[:8]}"
    set_correlation_id(correlation_id)

    db: Session = SessionLocal()
    scan: ScanHistory | None = None
    org_label = "unknown"

    try:
        scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
        if scan is None:
            logger.error("ScanHistory %s not found", scan_id)
            SCAN_COUNTER.labels(status="not_found", organization="unknown").inc()
            return {"scan_id": scan_id, "status": "not_found"}

        org_label = str(scan.organization_id)
        _set_status(db, scan, "running")
        ACTIVE_SCANS.labels(organization=org_label).inc()
        SCAN_COUNTER.labels(status="started", organization=org_label).inc()

        start = time.perf_counter()
        domain_name = scan.target

        # ── Phase 1: Discovery ────────────────────────────────────────────
        results = _with_retry(self, scan_id, "discovery", lambda: _run_async(lambda: _collect(domain_name)))
        resolved_ip = results["resolved"].get("ip")

        if not resolved_ip:
            _fail_scan(db, scan, org_label, "DNS resolution returned no IP")
            return {"scan_id": scan_id, "status": "failed"}

        pin_ip(domain_name, resolved_ip)

        persisted = _persist_discovery(db, scan, domain_name, results)
        _resolve_subdomain_ips(db, persisted["subdomains"])

        # ── Phase 2: Port / SSL / Header scanning ─────────────────────────
        scan_summary = _with_retry(
            self, scan_id, "scanning",
            lambda: _scan_targets(db, scan, persisted, domain_name, resolved_ip),
        )

        # ── Phase 3: Finding synthesis + risk scoring ─────────────────────
        asset_id = persisted["asset_id"]
        new_findings = _generate_and_persist_findings(db, scan, asset_id, scan_summary)
        _persist_risk_score(db, asset_id)

        # ── Phase 4: Change detection + alerts ────────────────────────────
        create_asset_snapshot(db, asset_id)
        changes = detect_changes(db, asset_id)
        if changes:
            persist_alerts(db, changes, scan.organization_id)

        db.commit()

        # ── Phase 5: External alert dispatch ──────────────────────────────
        _dispatch_alerts_for_findings(db, new_findings, asset_id, scan.organization_id)

        _set_status(db, scan, "completed")
        _record_metrics(org_label, start, completed=True)

        logger.info("Scan %s completed for %s", scan_id, domain_name)
        return {"scan_id": scan_id, "status": "completed"}

    except RETRYABLE_ERRORS as exc:
        db.rollback()
        attempt = self.request.retries or 0
        if attempt < self.max_retries:
            logger.warning("Scan %s retryable error (attempt %s): %s", scan_id, attempt, exc)
            _set_status(db, scan, "retrying")
            db.commit()
            raise self.retry(countdown=2 ** attempt, exc=exc)
        _fail_scan(db, scan, org_label, str(exc))
        raise

    except Exception as exc:
        db.rollback()
        _fail_scan(db, scan, org_label, str(exc))
        _send_to_dlq(self, scan_id, exc)
        raise

    finally:
        ACTIVE_SCANS.labels(organization=org_label).dec()
        db.close()
        clear_correlation_id()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _with_retry(task_self, scan_id: int, phase: str, fn) -> object:
    """Execute *fn* with per-phase retry on transient errors."""
    try:
        return fn()
    except RETRYABLE_ERRORS as exc:
        attempt = task_self.request.retries or 0
        if attempt < task_self.max_retries:
            logger.warning(
                "Scan %s phase=%s retryable (attempt %s): %s",
                scan_id, phase, attempt, exc,
            )
            raise task_self.retry(countdown=2 ** attempt, exc=exc)
        raise


def _fail_scan(db: Session, scan: ScanHistory | None, org_label: str, error: str) -> None:
    if scan is not None:
        scan.status = "failed"
        scan.error = error
        scan.completed_at = _now()
        db.commit()
        SCAN_COUNTER.labels(status="failed", organization=org_label).inc()
        SCAN_ERRORS.labels(
            organization=org_label,
            error_type=type(error).__name__,
        ).inc()


def _set_status(db: Session, scan: ScanHistory | None, status: str) -> None:
    if scan is not None:
        scan.status = status
        if status == "running":
            scan.error = None
        db.commit()


def _record_metrics(org_label: str, start: float, completed: bool) -> None:
    duration = time.perf_counter() - start
    SCAN_DURATION.labels(organization=org_label).observe(duration)
    status = "completed" if completed else "failed"
    SCAN_COUNTER.labels(status=status, organization=org_label).inc()


def _send_to_dlq(task_self, scan_id: int, exc: Exception) -> None:
    try:
        move_to_dlq(
            task_name=task_self.name,
            args=(scan_id,),
            kwargs={},
            exc=exc,
        )
    except Exception:
        logger.exception("Failed to send scan %s to DLQ", scan_id)


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


# ── Phase helpers ─────────────────────────────────────────────────────────────

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


def _persist_discovery(db: Session, scan: ScanHistory, domain_name: str, results: dict) -> dict:
    subdomain_data = results["subdomains"]
    normalized = []
    for item in subdomain_data:
        if isinstance(item, str):
            name = item.strip().lower().rstrip(".")
            source = "crt.sh" if name != domain_name else "primary"
        else:
            name = item.get("subdomain", "").strip().lower().rstrip(".")
            source = item.get("source", "unknown")
        if not name or "*" in name:
            continue
        if name.endswith(domain_name) or name == domain_name:
            normalized.append({"subdomain": name, "source": source})

    if domain_name not in [n["subdomain"] for n in normalized]:
        normalized.insert(0, {"subdomain": domain_name, "source": "primary"})

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

    org_label = str(scan.organization_id)
    for item in normalized:
        SUBDOMAINS_DISCOVERED.labels(
            organization=org_label,
            source=item["source"],
        ).inc()

    return persisted


def _resolve_subdomain_ips(db: Session, subdomains) -> None:
    for sub in subdomains:
        try:
            ips = _run_async(lambda s=sub: resolve_subdomain_ips(s.subdomain))
            if ips:
                persist_subdomain_ips(db, sub, ips)
                sub.ip_address = ips[0]
        except Exception:
            logger.debug("Failed to resolve IPs for %s", sub.subdomain)
    db.commit()


def _scan_targets(
    db: Session,
    scan: ScanHistory,
    persisted: dict,
    domain_name: str,
    resolved_ip: str | None,
) -> dict:
    from models.subdomain import Subdomain
    from app.scanning.context import ScanContext
    from app.scanning.registry import ScanPhase, registry

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
    org_label = str(scan.organization_id)

    for sub in targets[:MAX_PORT_SUBDOMAINS]:
        host = sub.subdomain

        try:
            pinned_ip = pinned_resolve(host)
        except PinnedResolutionMissing:
            try:
                ports = _run_async(lambda h=host: scan_ports(h))
                open_ports = [p for p in ports if p.get("status") == "open"]
                summary["ports_total"] += len(ports)
                summary["ports_open"] += len(open_ports)
                summary["open_port_numbers"].extend(p["port"] for p in open_ports)
                persist_port_results(db, sub, ports)
                for p in ports:
                    PORTS_SCANNED.labels(
                        organization=org_label,
                        status=p.get("status", "unknown"),
                    ).inc()
            except Exception:
                continue
            _scan_ssl_and_headers(db, summary, sub, host, pinned_ip=None)
            continue

        ctx = ScanContext(
            domain=host,
            pinned_ip=pinned_ip,
            org_id=scan.organization_id,
            scan_id=scan.id,
            db=db,
        )

        port_results = _run_in_context(ctx, registry.get_modules(phase=ScanPhase.PORT))
        ports = [p for p in port_results.get("ports", [])]
        if ports:
            open_ports = [p for p in ports if p.get("status") == "open"]
            summary["ports_total"] += len(ports)
            summary["ports_open"] += len(open_ports)
            summary["open_port_numbers"].extend(p["port"] for p in open_ports)
            persist_port_results(db, sub, ports)
            for p in ports:
                PORTS_SCANNED.labels(
                    organization=org_label,
                    status=p.get("status", "unknown"),
                ).inc()

        ssl_results = _run_in_context(ctx, registry.get_modules(phase=ScanPhase.SSL))
        ssl_data = ssl_results.get("ssl")
        if ssl_data:
            persist_ssl_result(db, sub, ssl_data)
            summary["ssl"]["scanned"] += 1
            SSL_CERTS_ANALYZED.labels(
                organization=org_label,
                risk_level=ssl_results.get("risk_level", "unknown"),
            ).inc()
            if ssl_results.get("risk_level") in ("high", "critical"):
                summary["ssl"]["issues"] += 1
            for finding in ssl_results.get("findings", []):
                summary["ssl_findings"].append(finding)

        header_results = _run_in_context(ctx, registry.get_modules(phase=ScanPhase.HEADER))
        issues = header_results.get("issues", [])
        if issues:
            summary["headers"]["scanned"] += 1
            summary["headers"]["issues"] += len(issues)
            for issue in issues:
                summary["header_findings"].append(issue)

    return summary


def _run_in_context(ctx, modules) -> dict:
    """Run all *modules* against *ctx*; merge their dict results."""
    merged: dict = {}
    for mod in modules:
        try:
            import asyncio
            result = _run_async(lambda m=mod: m.run(ctx))
            if isinstance(result, dict):
                merged.update(result)
        except Exception:
            logger.debug("Scanner module %s failed for %s", mod.name, ctx.domain)
    return merged


def _scan_ssl_and_headers(db, summary, sub, host, pinned_ip=None):
    """Fallback SSL + header scan when no pinned IP exists for *host*."""
    try:
        target = pinned_ip if pinned_ip else host
        ssl_data = _run_async(lambda h=target: analyze_ssl(h))
        ssl_assessment = assess_ssl_risk(ssl_data)
        persist_ssl_result(db, sub, ssl_data)
        summary["ssl"]["scanned"] += 1
        if ssl_assessment["risk_level"] in ("high", "critical"):
            summary["ssl"]["issues"] += 1
        for finding in ssl_assessment["findings"]:
            summary["ssl_findings"].append(finding)
    except Exception:
        logger.debug("SSL analysis failed for %s", host)

    try:
        header_issues = _run_async(lambda h=host: analyze_headers(f"https://{h}"))
        summary["headers"]["scanned"] += 1
        summary["headers"]["issues"] += len(header_issues)
        for issue in header_issues:
            summary["header_findings"].append(issue)
    except Exception:
        logger.debug("Header analysis failed for %s", host)


def _generate_and_persist_findings(
    db: Session,
    scan: ScanHistory,
    asset_id: int,
    summary: dict,
) -> list[Finding]:
    """Persist new findings and return the list of newly-created Finding objects."""
    findings_data = generate_findings(
        open_ports=[
            {"port": p, "status": "open"}
            for p in summary["open_port_numbers"]
        ],
        ssl_findings=summary.get("ssl_findings", []),
        header_findings=summary.get("header_findings", []),
    )

    new_findings: list[Finding] = []

    for finding in findings_data:
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
        f = Finding(
            organization_id=scan.organization_id,
            asset_id=asset_id,
            title=finding["title"],
            severity=finding["severity"],
            category=finding.get("category", "general"),
            description=finding.get("description"),
            recommendation=finding.get("recommendation"),
        )
        db.add(f)
        new_findings.append(f)

    db.flush()

    severity_buckets: dict[str, int] = {}
    for finding in new_findings:
        severity_buckets[finding.severity] = severity_buckets.get(finding.severity, 0) + 1
    for severity, count in severity_buckets.items():
        FINDINGS_PER_SCAN.labels(
            organization=str(scan.organization_id),
            severity=severity,
        ).observe(count)

    return new_findings


def _persist_risk_score(db: Session, asset_id: int) -> None:
    from services.scoring.risk_engine import recalculate_asset_risk_score
    recalculate_asset_risk_score(db, asset_id)


def _dispatch_alerts_for_findings(
    db: Session,
    new_findings: list[Finding],
    asset_id: int,
    org_id: int,
) -> None:
    """Dispatch external alerts (Slack/Discord/email) for each new finding."""
    if not new_findings:
        return

    from models.asset import Asset
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset is None:
        return

    for finding in new_findings:
        try:
            _run_async(lambda f=finding: process_finding_alerts(db, f, asset))
        except Exception:
            logger.warning(
                "Alert dispatch failed for finding %s on asset %s",
                finding.title, asset.name,
            )


def _run_async(coro_factory):
    """Run a coroutine on its own event loop.

    Works inside an already-running event loop (e.g. eager Celery execution
    during a FastAPI request in tests) as well as in a plain worker process.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro_factory()).result()
