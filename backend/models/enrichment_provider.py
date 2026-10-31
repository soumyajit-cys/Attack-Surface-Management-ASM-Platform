"""Enrichment provider configuration per organisation.

Stores configuration for optional key-based discovery/enrichment providers
(Shodan/Censys/SecurityTrails style).  The API key is stored Fernet-encrypted
at rest (see app/core/crypto.py) via the ``EncryptedText`` type and is never
returned by the API or logged.  Providers are disabled unless a row exists
here for the organisation.

Tenant-scoped: every row carries ``organization_id`` and is reached through
the owning organisation, consistent with the other tenant tables.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import relationship

from app.core.crypto import EncryptedText
from models.base import Base


class EnrichmentProvider(Base):

    __tablename__ = "enrichment_providers"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String, nullable=False)

    provider_type = Column(String, nullable=False)

    encrypted_api_key = Column(EncryptedText, nullable=True)

    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=True,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=True,
    )

    __table_args__ = (
        # One provider name per organisation.
        sa.UniqueConstraint(
            "organization_id",
            "name",
            name="uq_enrichment_providers_org_name",
        ),
    )

    organization = relationship(
        "Organization",
        back_populates="enrichment_providers",
    )
