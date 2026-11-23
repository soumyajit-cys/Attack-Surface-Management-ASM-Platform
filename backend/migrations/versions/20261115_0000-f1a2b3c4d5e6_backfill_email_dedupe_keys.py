"""Backfill email_security dedupe_keys to include domain.

This migration was moved out of e7f8a9b0c1d2 to ensure it runs as its own
revision, since the backfill may have been applied separately.

Revision ID: f1a2b3c4d5e6
Revises: b2c3d4e5f6a7
Create Date: 2026-11-15
"""

import re
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b")


def upgrade() -> None:
    conn = op.get_bind()
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
    pass
