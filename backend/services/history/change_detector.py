import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from models.asset_snapshot import AssetSnapshot
from models.asset import Asset
from models.alert import Alert
from models.subdomain import Subdomain
from models.port import Port
from models.ssl_result import SSLResult
from models.finding import Finding
from utils.logger import logger


def create_asset_snapshot(db: Session, asset_id: int) -> AssetSnapshot:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return None

    domains = []
    for domain in asset.domains:
        subdomains = []
        for sub in domain.subdomains:
            ports = []
            for port in sub.ports:
                if port.status == "open":
                    ports.append({
                        "port": port.port,
                        "service": port.service,
                        "protocol": port.protocol,
                        "banner": port.banner,
                    })
            ssl_result = sub.ssl_results[0] if sub.ssl_results else None
            ssl_data = None
            if ssl_result:
                ssl_data = {
                    "issuer": ssl_result.issuer,
                    "tls_version": ssl_result.tls_version,
                    "cipher": ssl_result.cipher,
                    "expires_at": ssl_result.expires_at.isoformat() if ssl_result.expires_at else None,
                    "self_signed": ssl_result.self_signed,
                    "risk_level": ssl_result.risk_level,
                }
            subdomains.append({
                "subdomain": sub.subdomain,
                "ip_address": sub.ip_address,
                "source": sub.source,
                "ports": ports,
                "ssl": ssl_data,
            })
        domains.append({
            "domain": domain.domain,
            "subdomains": subdomains,
        })

    findings = []
    for finding in asset.findings:
        findings.append({
            "title": finding.title,
            "severity": finding.severity,
            "category": finding.category,
        })

    snapshot_data = {
        "asset_id": asset_id,
        "asset_name": asset.name,
        "criticality": asset.criticality,
        "domains": domains,
        "findings": findings,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }

    snapshot = AssetSnapshot(
        asset_id=asset_id,
        snapshot=snapshot_data,
    )
    db.add(snapshot)
    db.flush()
    return snapshot


def get_previous_snapshot(db: Session, asset_id: int) -> Optional[AssetSnapshot]:
    return db.query(AssetSnapshot).filter(
        AssetSnapshot.asset_id == asset_id
    ).order_by(AssetSnapshot.created_at.desc()).offset(1).first()


def detect_changes(db: Session, asset_id: int) -> list[dict]:
    current = db.query(AssetSnapshot).filter(
        AssetSnapshot.asset_id == asset_id
    ).order_by(AssetSnapshot.created_at.desc()).first()

    previous = get_previous_snapshot(db, asset_id)

    if not current or not previous:
        return []

    current_data = current.snapshot
    previous_data = previous.snapshot

    changes = []

    changes.extend(_diff_subdomains(current_data, previous_data, asset_id))
    changes.extend(_diff_ports(current_data, previous_data, asset_id))
    changes.extend(_diff_ssl(current_data, previous_data, asset_id))
    changes.extend(_diff_findings(current_data, previous_data, asset_id))

    return changes


def _diff_subdomains(current: dict, previous: dict, asset_id: int) -> list[dict]:
    changes = []
    current_subs = _flatten_subdomains(current)
    previous_subs = _flatten_subdomains(previous)

    current_set = set(current_subs.keys())
    previous_set = set(previous_subs.keys())

    added = current_set - previous_set
    removed = previous_set - current_set

    for sub in added:
        changes.append({
            "type": "subdomain_added",
            "asset_id": asset_id,
            "title": f"New subdomain discovered: {sub}",
            "severity": "info",
            "details": json.dumps({"subdomain": sub, "source": current_subs[sub].get("source")}),
        })

    for sub in removed:
        changes.append({
            "type": "subdomain_removed",
            "asset_id": asset_id,
            "title": f"Subdomain no longer resolves: {sub}",
            "severity": "low",
            "details": json.dumps({"subdomain": sub}),
        })

    return changes


def _flatten_subdomains(data: dict) -> dict:
    result = {}
    for domain in data.get("domains", []):
        for sub in domain.get("subdomains", []):
            result[sub["subdomain"]] = sub
    return result


def _diff_ports(current: dict, previous: dict, asset_id: int) -> list[dict]:
    changes = []
    current_ports = _flatten_ports(current)
    previous_ports = _flatten_ports(previous)

    current_set = set(current_ports.keys())
    previous_set = set(previous_ports.keys())

    added = current_set - previous_set
    removed = previous_set - current_set

    for key in added:
        port_info = current_ports[key]
        changes.append({
            "type": "port_opened",
            "asset_id": asset_id,
            "title": f"New open port: {port_info['subdomain']}:{port_info['port']}",
            "severity": "medium",
            "details": json.dumps(port_info),
        })

    for key in removed:
        port_info = previous_ports[key]
        changes.append({
            "type": "port_closed",
            "asset_id": asset_id,
            "title": f"Port closed: {port_info['subdomain']}:{port_info['port']}",
            "severity": "low",
            "details": json.dumps(port_info),
        })

    return changes


def _flatten_ports(data: dict) -> dict:
    result = {}
    for domain in data.get("domains", []):
        for sub in domain.get("subdomains", []):
            for port in sub.get("ports", []):
                key = f"{sub['subdomain']}:{port['port']}"
                result[key] = {**port, "subdomain": sub["subdomain"]}
    return result


def _diff_ssl(current: dict, previous: dict, asset_id: int) -> list[dict]:
    changes = []
    current_ssl = _flatten_ssl(current)
    previous_ssl = _flatten_ssl(previous)

    all_subs = set(current_ssl.keys()) | set(previous_ssl.keys())

    for sub in all_subs:
        curr = current_ssl.get(sub)
        prev = previous_ssl.get(sub)

        if curr and not prev:
            changes.append({
                "type": "ssl_new",
                "asset_id": asset_id,
                "title": f"New SSL certificate on {sub}",
                "severity": "info",
                "details": json.dumps(curr),
            })
        elif prev and not curr:
            changes.append({
                "type": "ssl_removed",
                "asset_id": asset_id,
                "title": f"SSL certificate removed from {sub}",
                "severity": "medium",
                "details": json.dumps(prev),
            })
        elif curr and prev:
            if curr.get("expires_at") != prev.get("expires_at"):
                changes.append({
                    "type": "ssl_expiry_changed",
                    "asset_id": asset_id,
                    "title": f"SSL certificate expiry changed on {sub}",
                    "severity": "low",
                    "details": json.dumps({"old": prev.get("expires_at"), "new": curr.get("expires_at")}),
                })
            if curr.get("risk_level") != prev.get("risk_level"):
                severity = "high" if curr.get("risk_level") in ("high", "critical") else "medium"
                changes.append({
                    "type": "ssl_risk_changed",
                    "asset_id": asset_id,
                    "title": f"SSL risk level changed on {sub}: {prev.get('risk_level')} -> {curr.get('risk_level')}",
                    "severity": severity,
                    "details": json.dumps({"old": prev.get("risk_level"), "new": curr.get("risk_level")}),
                })

    return changes


def _flatten_ssl(data: dict) -> dict:
    result = {}
    for domain in data.get("domains", []):
        for sub in domain.get("subdomains", []):
            if sub.get("ssl"):
                result[sub["subdomain"]] = sub["ssl"]
    return result


def _diff_findings(current: dict, previous: dict, asset_id: int) -> list[dict]:
    changes = []
    current_findings = {(f["title"], f["severity"]): f for f in current.get("findings", [])}
    previous_findings = {(f["title"], f["severity"]): f for f in previous.get("findings", [])}

    current_set = set(current_findings.keys())
    previous_set = set(previous_findings.keys())

    added = current_set - previous_set
    removed = previous_set - current_set

    for key in added:
        f = current_findings[key]
        changes.append({
            "type": "finding_new",
            "asset_id": asset_id,
            "title": f"New finding: {f['title']}",
            "severity": f["severity"],
            "details": json.dumps(f),
        })

    for key in removed:
        f = previous_findings[key]
        changes.append({
            "type": "finding_resolved",
            "asset_id": asset_id,
            "title": f"Finding resolved: {f['title']}",
            "severity": "info",
            "details": json.dumps(f),
        })

    return changes


def persist_alerts(db: Session, changes: list[dict], organization_id: int) -> list[Alert]:
    """Persist change-detection alerts and return the created Alert objects.

    External notification (Slack/Discord) is handled by the caller in
    ``tasks.discovery_tasks`` after this returns.
    """
    if not changes:
        return []

    now = datetime.now(timezone.utc)
    created: list[Alert] = []

    for change in changes:
        alert = Alert(
            organization_id=organization_id,
            asset_id=change.get("asset_id"),
            title=change.get("title"),
            severity=change.get("severity", "info"),
            message=change.get("details"),
            created_at=now,
            updated_at=now,
        )
        db.add(alert)
        created.append(alert)

    db.flush()
    return created