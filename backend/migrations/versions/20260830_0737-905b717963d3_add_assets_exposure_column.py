"""add assets exposure column

Revision ID: 905b717963d3
Revises: 79f42e81b644
Create Date: 2026-08-30 07:37:21.149430

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '905b717963d3'
down_revision: Union[str, None] = '79f42e81b644'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'assets',
        sa.Column('exposure', sa.String(), nullable=False, server_default='internet'),
    )


def downgrade() -> None:
    op.drop_column('assets', 'exposure')