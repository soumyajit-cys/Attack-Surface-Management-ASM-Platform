"""Encrypt alert_integrations.webhook_url in place (data-only migration)

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-10-09

Phase 1 task 1.4 decision D: Slack/Discord webhook URLs are bearer
credentials and join the encrypted columns (same idempotent ``enc:v1:``
behavior, batch transaction, shared functions). Downgrade restores
plaintext; wrong-key downgrade fails loudly with no partial writes.
Back up the database first.
"""

from typing import Sequence, Union

from alembic import op


revision: str = 'c0d1e2f3a4b5'
down_revision: Union[str, None] = 'b9c0d1e2f3a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from app.core.crypto import encrypt_existing_rows

    counts = encrypt_existing_rows(op.get_bind())
    total = sum(counts.values())
    print(f"encrypt_secrets: encrypted {total} values {counts}")


def downgrade() -> None:
    from app.core.crypto import decrypt_existing_rows

    counts = decrypt_existing_rows(op.get_bind())
    total = sum(counts.values())
    print(f"encrypt_secrets: decrypted {total} values {counts}")
