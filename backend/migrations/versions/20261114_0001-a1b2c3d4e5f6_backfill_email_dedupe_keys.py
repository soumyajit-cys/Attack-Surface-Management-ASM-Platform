"""Backfill email_security dedupe_keys to include domain.

Old keys like 'email_security:spf_missing' become
'email_security:spf_missing:<domain>' where the domain can be derived
from the finding title/description.  Rows where the domain cannot be
derived are left unchanged (they will not be merged by the Phase 4
unique index).

Revision ID: a1b2c3d4e5f6
Revises: 9a1b2c3d4e5f
Create Date: 2026-11-14
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "9a1b2c3d4e5f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Backfill: for findings with dedupe_key matching 'email_security:<type>'
    # (no domain suffix), try to extract the domain from the title/description.
    # If not derivable, leave as-is.
    conn = op.get_bind()
    # Find all email_security findings with old-style dedupe keys.
    rows = conn.execute(
        sa.text(
            "SELECT id, dedupe_key, title, description "
            "FROM findings "
            "WHERE dedupe_key LIKE 'email_security:%' "
            "  AND dedupe_key NOT LIKE 'email_security:%:%'"
        )
    ).fetchall()

    for row in rows:
        finding_id, old_key, title, description = row
        # Try to extract domain from title (e.g. "SPF record not published for example.com")
        # or description.  Simple heuristic: look for a domain-like token.
        import re
        domain = None
        text = (title or "") + " " + (description or "")
        # Look for domain pattern in text
        m = re.search(r"\b([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b", text)
        if m:
            domain = m.group(1)
        if domain:
            new_key = f"{old_key}:{domain}"
            conn.execute(
                sa.text(
                    "UPDATE findings SET dedupe_key = :new_key WHERE id = :fid"
                ),
                {"new_key": new_key, "fid": finding_id},
            )


def downgrade() -> None:
    # Cannot reliably reverse (domain info lost). No-op.
    pass