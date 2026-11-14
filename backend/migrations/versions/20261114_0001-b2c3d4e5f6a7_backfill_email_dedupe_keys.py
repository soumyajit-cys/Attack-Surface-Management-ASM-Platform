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
    conn = op.get_bind()

    # Get all email_security findings with old-style dedupe keys.
    rows = conn.execute(
        sa.text(
            "SELECT f.id, f.dedupe_key, f.title, f.description, f.asset_id "
            "FROM findings f "
            "WHERE f.dedupe_key LIKE 'email_security:%' "
            "  AND f.dedupe_key NOT LIKE 'email_security:%:%'"
        )
    ).fetchall()

    for row in rows:
        finding_id, old_key, title, description, asset_id = row

        # Get the domains registered to this asset's org.
        domain_rows = conn.execute(
            sa.text(
                "SELECT d.domain FROM domains d "
                "JOIN assets a ON a.id = d.asset_id "
                "WHERE a.id = :aid"
            ),
            {"aid": asset_id},
        ).fetchall()
        registered = {r[0] for r in domain_rows}

        domain = None
        if len(registered) == 1:
            domain = next(iter(registered))
        elif len(registered) > 1:
            # Accept a text token only when it exactly equals a registered domain.
            text = (title or "") + " " + (description or "")
            for m in _DOMAIN_RE.finditer(text):
                candidate = m.group(1)
                if candidate in registered:
                    domain = candidate
                    break

        if domain:
            new_key = f"{old_key}:{domain}"
            conn.execute(
                sa.text("UPDATE findings SET dedupe_key = :new_key WHERE id = :fid"),
                {"new_key": new_key, "fid": finding_id},
            )


def downgrade() -> None:
    # No-op: domain info cannot be reliably reversed.
    pass