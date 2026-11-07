"""Backfill legacy crt.sh source name to crt_sh.

Phase 2 introduced the crt.sh provider with name ``crt_sh`` but an early
string-path in ``tasks/discovery_tasks._persist_discovery`` wrote
``source = "crt.sh"`` (with a dot) for plain-string subdomain results.  This
migration normalizes both the scalar ``source`` column and the array
``sources`` column so every row uses the canonical provider name ``crt_sh``.

Revision ID: c3a7f1e9b2d4
Revises: 7a8b9c0d1e2f
Create Date: 2026-11-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c3a7f1e9b2d4"
down_revision: Union[str, None] = "7a8b9c0d1e2f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OLD = "crt.sh"
_NEW = "crt_sh"


def upgrade() -> None:
    # Scalar column.
    op.execute(
        sa.text(
            "UPDATE subdomains SET source = :new WHERE source = :old"
        ).bindparams(old=_OLD, new=_NEW)
    )
    # Array column: replace any element equal to the old name.
    op.execute(
        sa.text(
            """
            UPDATE subdomains
            SET sources = ARRAY(
                SELECT DISTINCT CASE WHEN unnest = :old THEN :new ELSE unnest END
                FROM unnest(sources) AS unnest
            )
            WHERE :old = ANY(sources)
            """
        ).bindparams(old=_OLD, new=_NEW)
    )


def downgrade() -> None:
    # Best-effort reverse: rename crt_sh back to crt.sh where present.
    op.execute(
        sa.text(
            "UPDATE subdomains SET source = :old WHERE source = :new"
        ).bindparams(old=_OLD, new=_NEW)
    )
    op.execute(
        sa.text(
            """
            UPDATE subdomains
            SET sources = ARRAY(
                SELECT DISTINCT CASE WHEN unnest = :new THEN :old ELSE unnest END
                FROM unnest(sources) AS unnest
            )
            WHERE :new = ANY(sources)
            """
        ).bindparams(old=_OLD, new=_NEW)
    )
