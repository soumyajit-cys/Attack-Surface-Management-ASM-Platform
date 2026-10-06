"""verified_domains table + grace-period grandfathering

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-10-06

Phase 1 task 1.1: scans require a verified (or still-valid grandfathered)
domain. Pre-existing footprint keeps scanning during the grace period:
one ``grandfathered`` row per distinct (organization_id, domain) found in
``domains``, plus per asset name behind a scan policy. ``expires_at`` is
now() + VERIFICATION_GRACE_DAYS (app setting, default 14). Grandfathered
rows carry a placeholder token and are never usable as challenges; each
scheduled run warns and raises an in-app alert until the owner verifies.

Downgrade drops the table, losing verification state (re-verify after any
re-upgrade). No pre-existing table is touched.
"""

from datetime import datetime, timedelta, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, None] = 'd5e6f7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _grace_days() -> int:
    try:
        from app.core.config import settings
        return int(settings.verification_grace_days)
    except Exception:
        return 14


def upgrade() -> None:
    op.create_table(
        'verified_domains',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('domain', sa.String(), nullable=False),
        sa.Column('method', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('token', sa.String(), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'domain',
                            name='uq_verified_domains_org_domain'),
    )
    op.create_index(op.f('ix_verified_domains_organization_id'),
                    'verified_domains', ['organization_id'], unique=False)

    grace_expires = datetime.now(timezone.utc) + timedelta(days=_grace_days())

    # Every already-known domain keeps scanning through the grace period.
    op.execute(
        sa.text(
            "INSERT INTO verified_domains "
            "(organization_id, domain, method, status, token, expires_at) "
            "SELECT DISTINCT organization_id, lower(domain), "
            "'grandfathered', 'grandfathered', 'grandfathered', :expires "
            "FROM domains ON CONFLICT (organization_id, domain) DO NOTHING"
        ).bindparams(expires=grace_expires)
    )
    # Belt and braces: asset names behind scan policies (same domain strings
    # the scheduler would scan).
    op.execute(
        sa.text(
            "INSERT INTO verified_domains "
            "(organization_id, domain, method, status, token, expires_at) "
            "SELECT DISTINCT a.organization_id, lower(a.name), "
            "'grandfathered', 'grandfathered', 'grandfathered', :expires "
            "FROM assets a JOIN scan_policies p ON p.asset_id = a.id "
            "ON CONFLICT (organization_id, domain) DO NOTHING"
        ).bindparams(expires=grace_expires)
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_verified_domains_organization_id'),
                  table_name='verified_domains')
    op.drop_table('verified_domains')
