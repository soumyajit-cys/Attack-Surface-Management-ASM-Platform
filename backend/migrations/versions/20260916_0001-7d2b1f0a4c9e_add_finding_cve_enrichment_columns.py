"""add finding CVE enrichment columns

Revision ID: 7d2b1f0a4c9e
Revises: 905b717963d3
Create Date: 2026-09-16

Adds ``findings.cve_ids`` (JSON list of matched CVE IDs from OSV.dev) and
``findings.cvss_score`` (highest matched CVSS base score, feeds risk scoring).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '7d2b1f0a4c9e'
down_revision: Union[str, None] = '905b717963d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('cve_ids', sa.JSON(), nullable=True))
    op.add_column('findings', sa.Column('cvss_score', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'cvss_score')
    op.drop_column('findings', 'cve_ids')
