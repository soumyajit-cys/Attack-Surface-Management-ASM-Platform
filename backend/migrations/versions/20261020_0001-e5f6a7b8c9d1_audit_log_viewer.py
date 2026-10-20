"""Audit log viewer: ip column + query indexes for audit-logs route (item 6).

Revision ID: e5f6a7b8c9d1
Revises: d4e5f6a7b8c9

Adds audit_logs.ip_address (nullable; captured by record_audit from the
single source-of-truth client-IP helper) and indexes the filters the
audit-log viewer queries:
  ix_audit_logs_org_created  (organization_id, created_at)
  ix_audit_logs_action       (action)
  ix_audit_logs_ip           (ip_address)

Downgrade drops the three indexes and the column; historical IP data is
not restorable after a downgrade (documented).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'e5f6a7b8c9d1'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("ip_address", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_audit_logs_org_created",
        "audit_logs",
        ["organization_id", sa.text("created_at")],
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_ip", "audit_logs", ["ip_address"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_ip", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_created", table_name="audit_logs")
    op.drop_column("audit_logs", "ip_address")
