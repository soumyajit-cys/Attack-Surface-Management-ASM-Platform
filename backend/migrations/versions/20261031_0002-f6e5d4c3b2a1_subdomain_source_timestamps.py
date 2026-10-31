"""Add subdomain source, first_seen and last_seen tracking.

Tracks which discovery source(s) observed each subdomain and when, so new
assets feed the change detector and the UI can show first/last sighting.

- ``sources`` (text array): the full set of sources that have observed the
  subdomain.  A host seen by multiple sources keeps the full set.
- ``first_seen`` / ``last_seen``: when the subdomain was first / last seen.
- Backfills existing rows: ``first_seen`` = ``last_seen`` = ``created_at``,
  ``sources`` = ``[source]`` (or empty array when ``source`` is NULL).
- Adds a unique constraint on (domain_id, subdomain) so discovery upserts
  (INSERT ... ON CONFLICT) are safe under concurrent scans; subdomains are
  reached via domain->asset->org for tenant isolation (no denormalised
  organisation_id column, see docs/rls-design.md).

Revision ID: f6e5d4c3b2a1
Revises: a1b2c3d4e5f6
Create Date: 2026-10-31
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f6e5d4c3b2a1"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_UNIQUE_NAME = "uq_subdomains_domain_subdomain"


def upgrade() -> None:
    op.add_column(
        "subdomains",
        sa.Column(
            "sources",
            postgresql.ARRAY(sa.String()),
            nullable=True,
            server_default=sa.text("'{}'"),
        ),
    )
    op.add_column(
        "subdomains",
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "subdomains",
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_unique_constraint(
        _UNIQUE_NAME, "subdomains", ["domain_id", "subdomain"]
    )
    # Backfill existing rows from created_at/source.
    op.execute(
        """
        UPDATE subdomains
        SET sources = COALESCE(sources, CASE WHEN source IS NOT NULL
                                             THEN ARRAY[source]
                                             ELSE '{}'::text[] END),
            first_seen = COALESCE(first_seen, created_at),
            last_seen = COALESCE(last_seen, created_at)
        """
    )


def downgrade() -> None:
    op.drop_constraint(_UNIQUE_NAME, "subdomains", type_="unique")
    op.drop_column("subdomains", "last_seen")
    op.drop_column("subdomains", "first_seen")
    op.drop_column("subdomains", "sources")
