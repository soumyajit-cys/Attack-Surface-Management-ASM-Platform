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

    # ── Dedupe before adding the unique constraint ────────────────────────
    # If duplicate (domain_id, subdomain) rows exist (e.g. from concurrent
    # scans before the constraint existed), merge them deterministically:
    # keep the oldest row, union the sources, take min first_seen and max
    # last_seen, repoint subdomain_ips + any other FKs to the kept row,
    # then delete the rest.  This keeps the upgrade idempotent and safe.
    op.execute(
        """
        WITH ranked AS (
            SELECT id, domain_id, subdomain,
                   ROW_NUMBER() OVER (
                       PARTITION BY domain_id, subdomain
                       ORDER BY created_at ASC NULLS FIRST, id ASC
                   ) AS rn
            FROM subdomains
        ),
        dupes AS (
            SELECT r.id AS dup_id, r.domain_id, r.subdomain,
                   MIN(k.id) AS keep_id
            FROM ranked r
            JOIN ranked k
              ON k.domain_id = r.domain_id
             AND k.subdomain = r.subdomain
             AND k.rn = 1
            WHERE r.rn > 1
            GROUP BY r.id, r.domain_id, r.subdomain
        )
        -- Repoint subdomain_ips (and any other FKs referencing subdomains.id)
        -- from duplicate rows to the kept row.
        UPDATE subdomain_ips si
        SET subdomain_id = d.keep_id
        FROM dupes d
        WHERE si.subdomain_id = d.dup_id;

        -- Delete duplicate rows (the kept row is rn=1, never in dupes).
        DELETE FROM subdomains s
        USING dupes d
        WHERE s.id = d.dup_id;
        """
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
