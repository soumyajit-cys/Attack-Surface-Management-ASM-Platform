"""Add dedupe_key and confidence columns to findings for rescan deduplication.

Scanner modules (email_security, subdomain_takeover, etc.) populate these
columns with stable keys per finding type (e.g. "email_security:spf_missing")
and confidence scores (0.0-1.0). Rescans update the existing finding by
dedupe_key instead of creating a duplicate.

Revision ID: 8f1a2b3c4d5e
Revises: c3a7f1e9b2d4
Create Date: 2026-11-07
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "8f1a2b3c4d5e"
down_revision: Union[str, None] = "c3a7f1e9b2d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("dedupe_key", sa.String(), nullable=True, index=True),
    )
    op.add_column(
        "findings",
        sa.Column("confidence", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "confidence")
    op.drop_column("findings", "dedupe_key")
