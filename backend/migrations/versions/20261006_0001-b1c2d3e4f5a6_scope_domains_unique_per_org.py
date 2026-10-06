"""scope domains uniqueness to (organization_id, domain)

Revision ID: b1c2d3e4f5a6
Revises: 9f3c7e2b1a5d
Create Date: 2026-10-06

Fixes the multi-tenant hijack: ``domains.domain`` was globally unique, so
``services.scanner.persistence.get_or_create_domain`` looked rows up globally
and re-pointed them into the scanning tenant's asset. After this migration
two orgs may each own ``example.com`` as separate rows.

Safe on existing data: the old global UNIQUE(domain) already implies
UNIQUE(organization_id, domain), so upgrade cannot see composite duplicates.
The migration still checks explicitly and fails loudly instead of creating a
broken constraint. Downgrade re-creates the global constraint and therefore
checks for cross-org duplicate domain values first.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, None] = '9f3c7e2b1a5d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    dupes = list(conn.execute(sa.text(
        "SELECT organization_id, domain, COUNT(*) AS n "
        "FROM domains GROUP BY organization_id, domain HAVING COUNT(*) > 1"
    )))
    if dupes:
        raise RuntimeError(
            f"Cannot create UNIQUE(organization_id, domain): "
            f"{len(dupes)} duplicate (org, domain) pairs exist, e.g. {dupes[:5]}"
        )
    op.drop_constraint('domains_domain_key', 'domains', type_='unique')
    op.create_unique_constraint(
        'uq_domains_org_domain', 'domains', ['organization_id', 'domain']
    )


def downgrade() -> None:
    conn = op.get_bind()
    dupes = list(conn.execute(sa.text(
        "SELECT domain, COUNT(DISTINCT organization_id) AS orgs "
        "FROM domains GROUP BY domain HAVING COUNT(DISTINCT organization_id) > 1"
    )))
    if dupes:
        raise RuntimeError(
            f"Cannot restore UNIQUE(domain): "
            f"{len(dupes)} domains exist in >1 org, e.g. {dupes[:5]}. "
            f"Merge or rename them before downgrading."
        )
    op.drop_constraint('uq_domains_org_domain', 'domains', type_='unique')
    op.create_unique_constraint('domains_domain_key', 'domains', ['domain'])
