"""TOTP 2FA storage (Phase 1.5, task 1.5.4).

Revision ID: d4e5f6a7b8c9
Revises: c0d1e2f3a4b5

Adds users.totp_secret (plaintext-capable column; app-layer EncryptedText),
users.totp_enabled, users.totp_last_step, organizations.require_2fa, and the
recovery_codes table (SHA-256 hashed, single-use). Downgrade drops the table
and columns (2FA data is not restorable after downgrade -- documented).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c0d1e2f3a4b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret", sa.String(), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
    )
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(),
                                      nullable=True))
    op.add_column(
        "organizations",
        sa.Column("require_2fa", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
    )
    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("code_hash", sa.String(), nullable=False, unique=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("recovery_codes")
    op.drop_column("organizations", "require_2fa")
    op.drop_column("users", "totp_last_step")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret")
