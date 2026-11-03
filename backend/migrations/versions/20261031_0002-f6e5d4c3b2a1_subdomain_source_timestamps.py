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
        DO $$
        DECLARE
            rec RECORD;
            keep_id INTEGER;
        BEGIN
            FOR rec IN
                SELECT domain_id, subdomain
                FROM subdomains
                GROUP BY domain_id, subdomain
                HAVING COUNT(*) > 1
            LOOP
                -- Keep the oldest row (by created_at, then id).
                SELECT id INTO keep_id
                FROM subdomains
                WHERE domain_id = rec.domain_id
                  AND subdomain = rec.subdomain
                ORDER BY created_at ASC NULLS FIRST, id ASC
                LIMIT 1;

                -- Repoint subdomain_ips (and any other FKs referencing
                -- subdomains.id) from duplicate rows to the kept row.
                UPDATE subdomain_ips si
                SET subdomain_id = keep_id
                WHERE si.subdomain_id IN (
                    SELECT id FROM subdomains
                    WHERE domain_id = rec.domain_id
                      AND subdomain = rec.subdomain
                      AND id <> keep_id
                );

                -- Merge sources / timestamps into the kept row.
                UPDATE subdomains
                SET sources = (
                    SELECT ARRAY(
                        SELECT DISTINCT unnest(sources)
                        FROM subdomains
                        WHERE domain_id = rec.domain_id
                          AND subdomain = rec.subdomain
                    )
                ),
                first_seen = COALESCE(
                    (SELECT MIN(first_seen) FROM subdomains
                     WHERE domain_id = rec.domain_id
                       AND subdomain = rec.subdomain),
                    created_at
                ),
                last_seen = COALESCE(
                    (SELECT MAX(last_seen) FROM subdomains
                     WHERE domain_id = rec.domain_id
                       AND subdomain = rec.subdomain),
                    created_at
                )
                WHERE id = keep_id;

                -- Delete the duplicate rows (kept row is never deleted).
                DELETE FROM subdomains
                WHERE domain_id = rec.domain_id
                  AND subdomain = rec.subdomain
                  AND id <> keep_id;
            END LOOP;
        END $$;
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
