from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from models import Asset, Domain, Subdomain, Port, Finding, User
from utils.database import get_db

router = APIRouter(
    prefix="/graph",
    tags=["graph"],
)


@router.get("/asset/{asset_id}")
async def get_asset_graph(
    asset_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.organization_id == user.organization_id,
    ).first()
    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    nodes = []
    edges = []

    asset_node = {
        "id": f"asset-{asset.id}",
        "type": "asset",
        "label": asset.name,
        "data": {
            "id": asset.id,
            "name": asset.name,
            "criticality": asset.criticality,
        },
    }
    nodes.append(asset_node)

    for domain in asset.domains:
        domain_node = {
            "id": f"domain-{domain.id}",
            "type": "domain",
            "label": domain.domain,
            "data": {
                "id": domain.id,
                "domain": domain.domain,
                "registrar": domain.registrar,
                "asn": domain.asn,
            },
        }
        nodes.append(domain_node)
        edges.append({
            "source": f"asset-{asset.id}",
            "target": f"domain-{domain.id}",
            "type": "contains",
        })

        for sub in domain.subdomains:
            sub_node = {
                "id": f"subdomain-{sub.id}",
                "type": "subdomain",
                "label": sub.subdomain,
                "data": {
                    "id": sub.id,
                    "subdomain": sub.subdomain,
                    "ip_address": sub.ip_address,
                    "source": sub.source,
                },
            }
            nodes.append(sub_node)
            edges.append({
                "source": f"domain-{domain.id}",
                "target": f"subdomain-{sub.id}",
                "type": "resolves_to",
            })

            for port in sub.ports:
                if port.status == "open":
                    port_node = {
                        "id": f"port-{port.id}",
                        "type": "port",
                        "label": f"{port.port}/{port.protocol}",
                        "data": {
                            "id": port.id,
                            "port": port.port,
                            "protocol": port.protocol,
                            "service": port.service,
                            "banner": port.banner,
                            "status": port.status,
                        },
                    }
                    nodes.append(port_node)
                    edges.append({
                        "source": f"subdomain-{sub.id}",
                        "target": f"port-{port.id}",
                        "type": "exposes",
                    })

            for ssl in sub.ssl_results:
                ssl_node = {
                    "id": f"ssl-{ssl.id}",
                    "type": "ssl",
                    "label": f"SSL: {ssl.tls_version}",
                    "data": {
                        "id": ssl.id,
                        "issuer": ssl.issuer,
                        "tls_version": ssl.tls_version,
                        "cipher": ssl.cipher,
                        "expires_at": ssl.expires_at.isoformat() if ssl.expires_at else None,
                        "self_signed": ssl.self_signed,
                        "risk_level": ssl.risk_level,
                    },
                }
                nodes.append(ssl_node)
                edges.append({
                    "source": f"subdomain-{sub.id}",
                    "target": f"ssl-{ssl.id}",
                    "type": "secured_by",
                })

    for finding in asset.findings:
        finding_node = {
            "id": f"finding-{finding.id}",
            "type": "finding",
            "label": finding.title,
            "data": {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
            },
        }
        nodes.append(finding_node)
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