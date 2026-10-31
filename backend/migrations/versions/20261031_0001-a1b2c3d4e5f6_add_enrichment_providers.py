"""Add enrichment_providers table for optional discovery providers.

Stores per-organisation configuration for optional key-based discovery
providers (Shodan/Censys/SecurityTrails style).  The API key is stored
Fernet-encrypted at rest (see app/core/crypto.py) and is never returned by
the API or logged.  Providers are disabled unless a row exists here for the
organisation.

Revision ID: a1b2c3d4e5f6
Revises: e5f6a7b8c9d1
Create Date: 2026-10-31
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from app.core.crypto import EncryptedText

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "e5f6a7b8c9d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "enrichment_providers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("provider_type", sa.String(), nullable=False),
        sa.Column(
            "encrypted_api_key",
            EncryptedText(),
            nullable=True,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            onupdate=sa.text("now()"),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "organization_id",
            "name",
            name="uq_enrichment_providers_org_name",
        ),
    )


def downgrade() -> None:
    op.drop_table("enrichment_providers")
