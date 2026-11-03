"""``/api/v1/enrichment/providers`` -- enrichment provider management.

Admin-only (``enrichment:manage``).  GET returns only ``has_key`` /
``is_active`` -- the plaintext API key is never in a response or log.
PUT sets/rotates the Fernet-encrypted key and active flag; enabling any
third-party provider requires ``acknowledge_data_sharing=true``.  All
mutations are audited.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, status

from models import EnrichmentProvider, Organization
from schemas.enrichment import (
    EnrichmentProviderList,
    EnrichmentProviderResponse,
    EnrichmentProviderUpsert,
)

from app.core.audit import record_audit
from app.core.config import settings
from app.core.crypto import EncryptedText, encrypt_value, is_encrypted
from app.core.errors import BadRequestError, ConflictError, ForbiddenError
from app.core.permissions import Permission
from app.api.deps import Principal, require_permissions_dep
from app.db.session import get_db

router = APIRouter(prefix="/enrichment/providers", tags=["enrichment"])

_ENRICHMENT_DEP = require_permissions_dep(Permission.ENRICHMENT_MANAGE)


def _provider_response(p: EnrichmentProvider) -> EnrichmentProviderResponse:
    """Public view: never the key, only has_key + is_active."""
    return EnrichmentProviderResponse(
        name=p.name,
        provider_type=p.provider_type,
        has_key=p.encrypted_api_key is not None,
        is_active=p.is_active,
        created_at=p.created_at.isoformat() if p.created_at else None,
        updated_at=p.updated_at.isoformat() if p.updated_at else None,
    )


def _require_ack(provider_type: str, is_active: bool, acknowledge: bool) -> None:
    """Third-party providers need explicit data-sharing acknowledgement."""
    if is_active and provider_type not in ("crt_sh",):
        if not acknowledge:
            raise BadRequestError(
                "Enabling a third-party provider requires "
                "acknowledge_data_sharing=true",
                code="acknowledge_data_sharing_required",
            )


@router.get("", response_model=EnrichmentProviderList)
async def list_providers(
    db=Depends(get_db),
    principal: Principal = Depends(_ENRICHMENT_DEP),
):
    """List this org's enrichment providers (key material withheld)."""
    rows = (
        db.query(EnrichmentProvider)
        .filter(EnrichmentProvider.organization_id == principal.organization_id)
        .order_by(EnrichmentProvider.name)
        .all()
    )
    return EnrichmentProviderList(items=[_provider_response(r) for r in rows])


@router.put("/{name}", status_code=status.HTTP_200_OK)
async def upsert_provider(
    name: str,
    data: EnrichmentProviderUpsert,
    request: Request,
    db=Depends(get_db),
    principal: Principal = Depends(_ENRICHMENT_DEP),
):
    """Set or rotate a provider's encrypted API key and active flag.

    ``acknowledge_data_sharing=true`` is required to activate any
    third-party provider (crt.sh is exempt -- public CT logs only).
    """
    _require_ack(data.provider_type, data.is_active, data.acknowledge_data_sharing)

    row = (
        db.query(EnrichmentProvider)
        .filter(
            EnrichmentProvider.organization_id == principal.organization_id,
            EnrichmentProvider.name == name,
        )
        .first()
    )

    encrypted: Optional[str] = None
    if data.api_key is not None:
        encrypted = encrypt_value(data.api_key)
        if is_encrypted(data.api_key):
            raise BadRequestError(
                "Do not submit an already-encrypted value as api_key",
                code="already_encrypted",
            )

    if row is None:
        row = EnrichmentProvider(
            organization_id=principal.organization_id,
            name=name,
            provider_type=data.provider_type,
            encrypted_api_key=encrypted,
            is_active=data.is_active,
        )
        db.add(row)
        action = "enrichment.provider_created"
    else:
        row.provider_type = data.provider_type
        if encrypted is not None:
            row.encrypted_api_key = encrypted
        row.is_active = data.is_active
        row.updated_at = datetime.now(timezone.utc)
        action = "enrichment.provider_updated"

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action=action,
        details={
            "provider_name": name,
            "provider_type": data.provider_type,
            "is_active": data.is_active,
            "key_rotated": data.api_key is not None,
            "acknowledge_data_sharing": data.acknowledge_data_sharing,
        },
        request=request,
    )
    db.commit()
    return _provider_response(row)


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    name: str,
    request: Request,
    db=Depends(get_db),
    principal: Principal = Depends(_ENRICHMENT_DEP),
):
    """Remove an enrichment provider row for this org."""
    row = (
        db.query(EnrichmentProvider)
        .filter(
            EnrichmentProvider.organization_id == principal.organization_id,
            EnrichmentProvider.name == name,
        )
        .first()
    )
    if row is None:
        # Idempotent delete: missing provider is a no-op.
        return None

    db.delete(row)
    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="enrichment.provider_deleted",
        details={"provider_name": name, "provider_type": row.provider_type},
        request=request,
    )
    db.commit()
    return None
