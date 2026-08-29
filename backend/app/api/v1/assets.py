"""``/api/v1/assets`` -- asset inventory with nested scan results.

Replaces the missing legacy asset routes with a clean v1 surface:
- list with counts, pagination, search and filters,
- detail with nested domains / subdomains / ports / SSL,
- graph payload for the network-map view.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from models.asset import Asset
from models.subdomain import Subdomain
from models.port import Port
from models.finding import Finding

from app.core.errors import NotFoundError
from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db

router = APIRouter(prefix="/assets", tags=["assets"])

_READ_DEP = require_permissions_dep(Permission.FINDING_READ)


def _ssl_data(ssl) -> dict:
    return {
        "id": ssl.id,
        "issuer": ssl.issuer,
        "tls_version": ssl.tls_version,
        "cipher": ssl.cipher,
        "expires_at": ssl.expires_at.isoformat() if ssl.expires_at else None,
        "self_signed": ssl.self_signed,
        "risk_level": ssl.risk_level,
    }


def _port_data(port: Port) -> dict:
    return {
        "id": port.id,
        "port": port.port,
        "protocol": port.protocol,
        "service": port.service,
        "status": port.status,
        "banner": port.banner,
    }


def _subdomain_data(sub: Subdomain) -> dict:
    return {
        "id": sub.id,
        "subdomain": sub.subdomain,
        "ip_address": sub.ip_address,
        "source": sub.source,
        "ports": [_port_data(p) for p in sub.ports],
        "ssl": (
            _ssl_data(sub.ssl_results[0])
            if sub.ssl_results else None
        ),
    }


def _domain_data(domain) -> dict:
    return {
        "id": domain.id,
        "domain": domain.domain,
        "registrar": domain.registrar,
        "asn": domain.asn,
        "hosting_provider": domain.hosting_provider,
        "subdomains": [_subdomain_data(s) for s in domain.subdomains],
    }


def _risk_score(asset) -> float:
    latest = None
    for rs in asset.risk_scores:
        if latest is None or rs.created_at > latest.created_at:
            latest = rs
    return float(latest.score) if latest else 0.0


def _asset_counts(db: Session, org_id: int, assets) -> dict[int, dict]:
    """Per-asset counts keyed by asset_id."""
    ids = [a.id for a in assets]
    if not ids:
        return {}

    finding_counts = dict(
        db.query(Finding.asset_id, func.count(Finding.id))
        .filter(Finding.asset_id.in_(ids), Finding.organization_id == org_id)
        .group_by(Finding.asset_id)
        .all()
    )

    sub_ids = {
        s.id
        for a in assets
        for d in a.domains
        for s in d.subdomains
    }
    open_port_counts: dict[int, int] = {}
    if sub_ids:
        open_port_counts = dict(
            db.query(Subdomain.id, func.count(Port.id))
            .join(Port, Port.subdomain_id == Subdomain.id)
            .filter(Subdomain.id.in_(sub_ids), Port.status == "open")
            .group_by(Subdomain.id)
            .all()
        )

    result: dict[int, dict] = {}
    for a in assets:
        result[a.id] = {
            "domains_count": len(a.domains),
            "findings_count": finding_counts.get(a.id, 0),
            "open_ports": sum(
                open_port_counts.get(s.id, 0)
                for d in a.domains
                for s in d.subdomains
            ),
        }
    return result


@router.get("")
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = None,
    criticality: str | None = None,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_DEP),
):
    query = db.query(Asset).filter(
        Asset.organization_id == principal.organization_id
    )

    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(Asset.name.ilike(search_term))

    total = query.count()
    assets = (
        query.order_by(Asset.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    counts = _asset_counts(db, principal.organization_id, assets)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": a.id,
                "name": a.name,
                "criticality": a.criticality,
                "exposure": a.exposure,
                "created_at": a.created_at,
                "updated_at": a.updated_at,
                "risk_score": _risk_score(a),
                **counts.get(a.id, {}),
            }
            for a in assets
        ],
    }


@router.get("/{asset_id}")
async def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_DEP),
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.organization_id == principal.organization_id,
    ).first()
    if not asset:
        raise NotFoundError("Asset not found", code="asset_not_found")

    counts = _asset_counts(db, principal.organization_id, [asset])[asset.id]

    return {
        "id": asset.id,
        "name": asset.name,
        "criticality": asset.criticality,
        "exposure": asset.exposure,
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
        "risk_score": _risk_score(asset),
        **counts,
        "domains": [_domain_data(d) for d in asset.domains],
    }


@router.get("/{asset_id}/graph")
async def get_asset_graph(
    asset_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_READ_DEP),
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.organization_id == principal.organization_id,
    ).first()
    if not asset:
        raise NotFoundError("Asset not found", code="asset_not_found")

    nodes: list[dict] = []
    edges: list[dict] = []

    nodes.append({
        "id": f"asset-{asset.id}",
        "type": "asset",
        "label": asset.name,
        "data": {"id": asset.id, "name": asset.name, "criticality": asset.criticality},
    })

    for domain in asset.domains:
        nodes.append({
            "id": f"domain-{domain.id}",
            "type": "domain",
            "label": domain.domain,
            "data": {
                "id": domain.id,
                "domain": domain.domain,
                "registrar": domain.registrar,
                "asn": domain.asn,
            },
        })
        edges.append({
            "source": f"asset-{asset.id}",
            "target": f"domain-{domain.id}",
            "type": "contains",
        })

        for sub in domain.subdomains:
            nodes.append({
                "id": f"subdomain-{sub.id}",
                "type": "subdomain",
                "label": sub.subdomain,
                "data": {
                    "id": sub.id,
                    "subdomain": sub.subdomain,
                    "ip_address": sub.ip_address,
                    "source": sub.source,
                },
            })
            edges.append({
                "source": f"domain-{domain.id}",
                "target": f"subdomain-{sub.id}",
                "type": "resolves_to",
            })

            for port in sub.ports:
                if port.status != "open":
                    continue
                nodes.append({
                    "id": f"port-{port.id}",
                    "type": "port",
                    "label": f"{port.port}/{port.protocol}",
                    "data": _port_data(port),
                })
                edges.append({
                    "source": f"subdomain-{sub.id}",
                    "target": f"port-{port.id}",
                    "type": "exposes",
                })

            for ssl in sub.ssl_results:
                nodes.append({
                    "id": f"ssl-{ssl.id}",
                    "type": "ssl",
                    "label": f"SSL: {ssl.tls_version}",
                    "data": _ssl_data(ssl),
                })
                edges.append({
                    "source": f"subdomain-{sub.id}",
                    "target": f"ssl-{ssl.id}",
                    "type": "secured_by",
                })

    for finding in asset.findings:
        nodes.append({
            "id": f"finding-{finding.id}",
            "type": "finding",
            "label": finding.title,
            "data": {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
            },
        })
        edges.append({
            "source": f"asset-{asset.id}",
            "target": f"finding-{finding.id}",
            "type": "has_finding",
        })

    return {
        "asset_id": asset.id,
        "nodes": nodes,
        "edges": edges,
    }