"""ssl_results.expires_at: timestamp -> timestamptz, assuming UTC

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-10-06

All writers stamp UTC (`services.scanner.ssl_scanner._parse_cert` sets
tzinfo=timezone.utc), but the column was timezone-naive so Postgres stored
the wall time with the zone dropped. Existing rows are therefore interpreted
as UTC on upgrade. Comparisons in `_parse_cert` are already aware/aware, and
readers only isoformat the value, so no code change beyond the model type.
"""

from typing import Sequence, Union

from alembic import op


revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE ssl_results ALTER COLUMN expires_at TYPE TIMESTAMPTZ "
        "USING expires_at AT TIME ZONE 'UTC'"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE ssl_results ALTER COLUMN expires_at TYPE TIMESTAMP "
        "USING expires_at AT TIME ZONE 'UTC'"
    )
