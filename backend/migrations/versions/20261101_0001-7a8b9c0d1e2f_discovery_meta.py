"""Add discovery_meta JSONB column to scan_history.

Stores per-source truncation flags and counts from discover_subdomains
so the API can surface whether discovery results were capped.

Revision ID: 7a8b9c0d1e2f
Revises: f6e5d4c3b2a1
Create Date: 2026-11-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "7a8b9c0d1e2f"
down_revision: Union[str, None] = "f6e5d4c3b2a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_history",
        sa.Column(
            "discovery_meta",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_history", "discovery_meta")
