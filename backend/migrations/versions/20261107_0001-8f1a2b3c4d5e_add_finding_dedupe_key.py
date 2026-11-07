"""Add dedupe_key column to findings for rescan deduplication.

Scanner modules (email_security, subdomain_takeover, etc.) populate this
column with a stable key per finding type (e.g. "email_security:spf_missing").
Rescans update the existing finding by dedupe_key instead of creating a
duplicate.

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


def downgrade() -> None:
    op.drop_column("findings", "dedupe_key")
