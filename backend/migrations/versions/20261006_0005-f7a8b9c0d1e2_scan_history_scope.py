"""scan_history.scope: record which scope each scan ran under

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-10-06

Phase 1 task 1.2: the pipeline stamps the scope (passive/active/full) on the
scan row. Pre-existing rows ran the old always-full pipeline, so they
backfill to ``'full'`` via the server default. Downgrade drops the column.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f7a8b9c0d1e2'
down_revision: Union[str, None] = 'e6f7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scan_history',
        sa.Column('scope', sa.String(), nullable=False, server_default='full'),
    )


def downgrade() -> None:
    op.drop_column('scan_history', 'scope')
