from sqlalchemy.orm import Session

from models.asset import Asset
from models.domain import Domain
from models.dns_record import DNSRecord
from models.port import Port
from models.ssl_result import SSLResult
from models.subdomain import Subdomain
from models.subdomain_ip import subdomain_ips


def persist_subdomain_ips(db: Session, subdomain: Subdomain, ips: list[str]) -> None:
    if not ips:
        return
    for ip in ips:
        existing = db.query(subdomain_ips).filter(
            subdomain_ips.c.subdomain_id == subdomain.id,
            subdomain_ips.c.ip_address == ip,
        ).first()
        if existing is None:
            db.execute(subdomain_ips.insert().values(
                subdomain_id=subdomain.id,
                ip_address=ip,
            ))


def get_or_create_asset(db: Session, org_id: int, name: str) -> Asset:
    asset = (
        db.query(Asset)
        .filter(
            Asset.organization_id == org_id,
            Asset.name == name,
        )
        .first()
    )
    if asset is None:
        asset = Asset(
            organization_id=org_id,
            name=name,
        )
        db.add(asset)
        db.flush()
    return asset


def get_or_create_domain(
    db: Session,
    org_id: int,
    asset: Asset,
    domain_name: str,
) -> Domain:
    domain = (
        db.query(Domain)
        .filter(Domain.domain == domain_name)
        .first()
    )
    if domain is None:
        domain = Domain(
            organization_id=org_id,
            asset_id=asset.id,
            domain=domain_name,
        )
        db.add(domain)
        db.flush()
    else:
        domain.asset_id = asset.id
    return domain


def persist_discovery_results(
    db: Session,
    org_id: int,
    domain_name: str,
    results: dict,
) -> dict:
    asset = get_or_create_asset(db, org_id, domain_name)
    domain = get_or_create_domain(db, org_id, asset, domain_name)

    if results.get("registrar") or results.get("asn"):
        domain.registrar = results.get("registrar")
        domain.asn = results.get("asn")

    dns_records = results.get("dns", [])
    for record in dns_records:
        existing = (
            db.query(DNSRecord)
            .filter(
                DNSRecord.domain_id == domain.id,
                DNSRecord.record_type == record.get("type"),
                DNSRecord.value == record.get("value"),
            )
            .first()
        )
        if existing is None:
            db.add(DNSRecord(
                domain_id=domain.id,
                record_type=record.get("type"),
                value=record.get("value"),
            ))

    subdomains = results.get("subdomains", [])
    saved = []

    for sub in subdomains:
        name = sub.get("subdomain") or sub.get("name")
        if not name:
            continue

        existing = (
            db.query(Subdomain)
            .filter(
                Subdomain.domain_id == domain.id,
                Subdomain.subdomain == name,
            )
            .first()
        )
        if existing is None:
            existing = Subdomain(
                domain_id=domain.id,
                subdomain=name,
                source=sub.get("source", "unknown"),
            )
            db.add(existing)
            db.flush()

        if sub.get("ip_address"):
            existing.ip_address = sub["ip_address"]

        saved.append(existing)

    return {
        "asset_id": asset.id,
        "domain_id": domain.id,
        "subdomains": saved,
    }


def persist_port_results(
    db: Session,
    subdomain: Subdomain,
    ports: list,
) -> None:
    existing_ports = (
        db.query(Port)
        .filter(Port.subdomain_id == subdomain.id)
        .all()
    )
    existing_by_key = {
        p.port: p for p in existing_ports
    }

    seen = set()
    for port in ports:
        number = port.get("port")
        if not number:
            continue
        seen.add(number)
        status = port.get("status", "closed")
        if status == "closed":
            continue

        row = existing_by_key.get(number)
        if row is None:
            db.add(Port(
                subdomain_id=subdomain.id,
                port=number,
                service=port.get("service"),
                protocol=port.get("protocol", "tcp"),
                status=status,
            ))
        else:
            row.status = status
            if port.get("service"):
                row.service = port.get("service")
            if port.get("protocol"):
                row.protocol = port.get("protocol")

    for number, row in existing_by_key.items():
        if number not in seen:
            row.status = "closed"


def persist_ssl_result(
    db: Session,
    subdomain: Subdomain,
    ssl_data: dict | None,
) -> None:
    if not ssl_data:
        return

    existing = (
        db.query(SSLResult)
        .filter(SSLResult.subdomain_id == subdomain.id)
        .first()
    )
    if existing is None:
        existing = SSLResult(
            subdomain_id=subdomain.id,
            issuer=ssl_data.get("issuer"),
            tls_version=ssl_data.get("tls_version"),
            cipher=ssl_data.get("cipher"),
            expires_at=ssl_data.get("expires_at"),
            self_signed=ssl_data.get("self_signed"),
            risk_level=ssl_data.get("risk_level"),
        )
        db.add(existing)
    else:
        existing.issuer = ssl_data.get("issuer", existing.issuer)
        existing.tls_version = ssl_data.get("tls_version", existing.tls_version)
        existing.cipher = ssl_data.get("cipher", existing.cipher)
        existing.expires_at = ssl_data.get("expires_at", existing.expires_at)
        existing.self_signed = ssl_data.get("self_signed", existing.self_signed)
        existing.risk_level = ssl_data.get("risk_level", existing.risk_level)