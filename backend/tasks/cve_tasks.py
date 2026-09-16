"""CVE enrichment task: match banner-grabbed software against OSV.dev.

``enrich_asset_findings`` runs after a scan (or on demand via
``POST /api/v1/assets/{id}/enrich``): for every open port with a banner
that yields a known ``(product, version)`` pair it queries OSV.dev,
persists one ``vulnerability`` finding per matched CVE (with CVSS score),
recalculates the asset risk score, and dispatches alerts for the new
findings via the existing webhook/email pipeline.

Reliability mirrors ``tasks.discovery_tasks``: transient network errors
retry with exponential backoff; SSRF-guard violations fail closed without
retry; unexpected errors go to the DLQ. The task is idempotent — reruns
skip CVEs that already have a finding for the asset.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import socket

import requests

from models.asset import Asset
from models.domain import Domain
from models.finding import Finding
from models.port import Port
from models.subdomain import Subdomain
from services.enrichment.cve_service import enrich_service_banner
from utils.database import SessionLocal
from utils.logger import logger
from workers.celery_app import celery, move_to_dlq

RETRYABLE_ERRORS = (
    requests.RequestException,
    socket.gaierror,
    socket.timeout,
    TimeoutError,
    ConnectionError,
    OSError,
)


@celery.task(bind=True, name="tasks.cve.enrich_asset_findings", max_retries=3)
def enrich_asset_findings(self, asset_id: int) -> dict:
    """Enrich one asset's port findings with OSV.dev CVE matches."""
    from app.core.config import settings

    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset is None:
            logger.warning("enrich_asset_findings: asset %s not found", asset_id)
            return {"asset_id": asset_id, "status": "not_found"}

        if not settings.osv_enabled:
            return {"asset_id": asset_id, "status": "disabled"}

        ports = _open_ports_with_banners(db, asset_id)
        if not ports:
            return {"asset_id": asset_id, "status": "completed", "created": 0, "checked": 0}

        cache: dict[tuple, list[dict]] = {}
        new_findings: list[Finding] = []
        checked = 0

        for port, subdomain_name in ports:
            try:
                vulns = _cached_enrich(cache, port.service, port.banner)
            except ValueError as exc:
                # SSRF-guard violation: fail closed without retry.
                logger.error("enrich_asset_findings: feed blocked: %s", exc)
                return {"asset_id": asset_id, "status": "blocked", "error": str(exc)}
            checked += 1
            for vuln in vulns:
                title = (
                    f"{vuln['cve_id']} in {vuln['product']} {vuln['version']} "
                    f"on {subdomain_name}:{port.port}"
                )
                exists = (
                    db.query(Finding)
                    .filter(
                        Finding.organization_id == asset.organization_id,
                        Finding.asset_id == asset_id,
                        Finding.title == title,
                    )
                    .first()
                )
                if exists is not None:
                    continue
                finding = Finding(
                    organization_id=asset.organization_id,
                    asset_id=asset_id,
                    title=title,
                    severity=vuln["severity"],
                    category="vulnerability",
                    description=_describe(vuln, subdomain_name, port),
                    recommendation=(
                        f"Upgrade {vuln['product']} to a release patched for "
                        f"{vuln['cve_id']}, or apply the vendor mitigation. "
                        f"See https://osv.dev/vulnerability/{vuln['cve_id']}."
                    ),
                    cve_ids=[vuln["cve_id"]],
                    cvss_score=vuln["cvss"],
                )
                db.add(finding)
                new_findings.append(finding)

        db.flush()

        if new_findings:
            from services.scoring.risk_engine import recalculate_asset_risk_score

            recalculate_asset_risk_score(db, asset_id)
            db.commit()
            _dispatch_alerts(db, new_findings, asset)
        else:
            db.commit()

        logger.info(
            "enrich_asset_findings: asset=%s checked=%s created=%s",
            asset_id, checked, len(new_findings),
        )
        return {
            "asset_id": asset_id,
            "status": "completed",
            "checked": checked,
            "created": len(new_findings),
        }

    except RETRYABLE_ERRORS as exc:
        db.rollback()
        attempt = self.request.retries or 0
        if attempt < self.max_retries:
            logger.warning(
                "enrich_asset_findings asset=%s retryable (attempt %s): %s",
                asset_id, attempt, exc,
            )
            raise self.retry(countdown=2 ** attempt, exc=exc)
        logger.error("enrich_asset_findings asset=%s exhausted retries: %s", asset_id, exc)
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("enrich_asset_findings asset=%s failed: %s", asset_id, exc)
        try:
            move_to_dlq(task_name=self.name, args=(asset_id,), kwargs={}, exc=exc)
        except Exception:
            logger.exception("Failed to send enrichment task for asset %s to DLQ", asset_id)
        raise
    finally:
        db.close()


def _open_ports_with_banners(db, asset_id: int) -> list[tuple[Port, str]]:
    sub_rows = (
        db.query(Subdomain.id, Subdomain.subdomain)
        .join(Domain, Domain.id == Subdomain.domain_id)
        .filter(Domain.asset_id == asset_id)
        .all()
    )
    names = {row[0]: row[1] for row in sub_rows}
    if not names:
        return []
    ports = (
        db.query(Port)
        .filter(
            Port.subdomain_id.in_(list(names)),
            Port.status == "open",
            Port.banner.isnot(None),
        )
        .all()
    )
    return [(p, names.get(p.subdomain_id, "unknown")) for p in ports if p.banner]


def _cached_enrich(cache: dict, service: str | None, banner: str | None) -> list[dict]:
    from services.enrichment.cve_service import extract_software

    found = extract_software(banner, service)
    if not found:
        return []
    key = (found["product"], found["version"])
    if key not in cache:
        cache[key] = enrich_service_banner(service, banner)
    return cache[key]


def _describe(vuln: dict, subdomain_name: str, port: Port) -> str:
    lines = [
        f"{vuln['cve_id']} affects {vuln['product']} {vuln['version']} detected on "
        f"{subdomain_name}:{port.port} (service: {port.service or 'unknown'}).",
    ]
    if vuln.get("cvss") is not None:
        lines.append(f"CVSS base score: {vuln['cvss']} ({vuln['severity']}).")
    if vuln.get("summary"):
        lines.append(vuln["summary"])
    return "\n".join(lines)


def _dispatch_alerts(db, findings: list[Finding], asset: Asset) -> None:
    """Send webhook/email alerts for new CVE findings (best-effort)."""
    from services.alerts.alerting_service import process_finding_alerts

    for finding in findings:
        try:
            _run_async(lambda f=finding: process_finding_alerts(db, f, asset))
        except Exception:
            logger.warning(
                "CVE alert dispatch failed for finding %s on asset %s",
                finding.title, asset.name,
            )


def _run_async(coro_factory):
    """Run a coroutine on its own event loop (mirrors discovery_tasks)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro_factory()).result()
