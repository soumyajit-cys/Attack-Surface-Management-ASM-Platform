"""Backfill email_security dedupe_keys to include domain.

Old keys like 'email_security:spf_missing' become
'email_security:spf_missing:<domain>' where the domain is derived from
the finding's own asset (via domains->organization).  If the asset has
exactly one registered domain, that domain is used.  If it has several,
a text token is accepted only when it exactly equals one of the asset's
registered domains.  Otherwise the row is left unchanged (it will not be
merged by the Phase 4 unique index).

Downgrade is a no-op (domain info cannot be reliably reversed).

Revision ID: b2c3d4e5f6a7
Revises: 9a1b2c3d4e5f
Create Date: 2026-11-14
"""

import re
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "9a1b2c3d4e5f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Compiled once.
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b")


def upgrade() -> None:
    # Backfill moved to f1a2b3c4d5e6 (new revision). This migration is now
    # a no-op to avoid running the backfill twice on databases that already
    # applied the old version.
    pass


def downgrade() -> None:
    # No-op: domain info cannot be reliably reversed.
    pass