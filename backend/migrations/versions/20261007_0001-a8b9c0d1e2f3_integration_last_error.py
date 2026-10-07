"""alert_integrations.last_error/last_error_at: surface failing integrations

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-10-07

Phase 1 task 1.3 (decision C.3): integrations that fail validation or
delivery record the failure instead of failing silently. Both columns start
NULL (no known failure). Downgrade drops them.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a8b9c0d1e2f3'
down_revision: Union[str, None] = 'f7a8b9c0d1e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'alert_integrations',
        sa.Column('last_error', sa.Text(), nullable=True),
    )
    op.add_column(
        'alert_integrations',
        sa.Column('last_error_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('alert_integrations', 'last_error_at')
    op.drop_column('alert_integrations', 'last_error')
