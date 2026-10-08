"""Encrypt alert_integration secrets in place (data-only migration)

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-10-08

Phase 1 task 1.4: encrypts ``alert_integrations.secret`` and
``jira_api_token`` values that are still plaintext, via the same shared
function as scripts/encrypt_secrets.py. Rows already carrying the
``enc:v1:`` prefix are skipped, so re-running changes nothing. No schema
change: both columns are unbounded String, which holds Fernet tokens.

The key is required only when rows actually need encryption: with an
empty table the migration is a no-op. Otherwise a missing/invalid key
aborts loudly inside the Alembic transaction, so no partial writes occur.
Downgrade decrypts back to plaintext; without a working key it fails
loudly and changes nothing. Back up the database first.
"""

from typing import Sequence, Union

from alembic import op


revision: str = 'b9c0d1e2f3a4'
down_revision: Union[str, None] = 'a8b9c0d1e2f3'
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
