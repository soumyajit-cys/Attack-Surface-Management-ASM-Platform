"""alerts.read: Integer -> Boolean, preserving 0/1/NULL values

Revision ID: c4d5e6f7a8b9
Revises: b1c2d3e4f5a6
Create Date: 2026-10-06

Code has only ever written 0 (column default; persist_alerts leaves it unset)
and compared `read == 0`, so stored values are 0/1/NULL. The USING clause maps
them explicitly instead of relying on implicit casts. Downgrade maps back to
1/0/NULL.
"""

from typing import Sequence, Union

from alembic import op


revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, None] = 'b1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE alerts ALTER COLUMN read DROP DEFAULT")
    op.execute(
        "ALTER TABLE alerts ALTER COLUMN read TYPE BOOLEAN "
        "USING (CASE WHEN read IS NULL THEN NULL ELSE read <> 0 END)"
    )
    op.execute("ALTER TABLE alerts ALTER COLUMN read SET DEFAULT FALSE")


def downgrade() -> None:
    op.execute("ALTER TABLE alerts ALTER COLUMN read DROP DEFAULT")
    op.execute(
        "ALTER TABLE alerts ALTER COLUMN read TYPE INTEGER "
        "USING (CASE WHEN read IS NULL THEN NULL WHEN read THEN 1 ELSE 0 END)"
    )
    op.execute("ALTER TABLE alerts ALTER COLUMN read SET DEFAULT 0")
