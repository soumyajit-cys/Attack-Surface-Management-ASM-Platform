"""Phase 4a: findings workflow schema + identity migration.

Adds workflow columns to findings, creates finding_events, org_sla_config,
and scan_module_runs tables, backfills source_module/target_host/dedupe_key,
merges duplicates, adds unique index.

Revision ID: e7f8a9b0c1d2
Revises: b2c3d4e5f6a7
Create Date: 2026-11-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e7f8a9b0c1d2"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add new columns to findings (nullable first).
    op.add_column("findings", sa.Column("source_module", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("target_host", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("last_seen_scan_id", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("version", sa.Integer(), server_default="1", nullable=False))
    op.add_column("findings", sa.Column("status", sa.String(), server_default="open", nullable=False))
    op.add_column("findings", sa.Column("assigned_to", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("due_date", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("resolved_by", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("suppression_reason", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("suppressed_by", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("sla_alerted_at", sa.DateTime(timezone=True), nullable=True))

    # Backfill first_seen_at from created_at.
    op.execute("UPDATE findings SET first_seen_at = created_at WHERE first_seen_at IS NULL")

    # Backfill source_module and target_host from dedupe_key.
    # email_security: email_security:<type>:<domain>
    op.execute("""
        UPDATE findings SET source_module = 'email_security', target_host = split_part(dedupe_key, ':', 3)
        WHERE dedupe_key LIKE 'email_security:%:%'
    """)
    # subdomain_takeover: subdomain_takeover:<provider>:<host>
    op.execute("""
        UPDATE findings SET source_module = 'subdomain_takeover', target_host = split_part(dedupe_key, ':', 3)
        WHERE dedupe_key LIKE 'subdomain_takeover:%:%'
    """)
    # tech_fingerprint: tech_fingerprint:<tech>:<host>
    op.execute("""
        UPDATE findings SET source_module = 'tech_fingerprint', target_host = split_part(dedupe_key, ':', 3)
        WHERE dedupe_key LIKE 'tech_fingerprint:%:%'
    """)
    # exposed_services: exposed_services:<sig>:<host>:<port>[:path]
    op.execute("""
        UPDATE findings SET source_module = 'exposed_services', target_host = split_part(dedupe_key, ':', 3)
        WHERE dedupe_key LIKE 'exposed_services:%'
    """)
    # ssl_*: ssl_scan, host from suffix after last colon
    op.execute("""
        UPDATE findings SET source_module = 'ssl_scan',
            target_host = split_part(dedupe_key, ':', 2)
        WHERE dedupe_key LIKE 'ssl\\_%' ESCAPE '\\'
    """)

    # Backfill dedupe_key for legacy title-keyed findings.
    # (Use md5 of title as fallback key.)
    op.execute("""
        UPDATE findings SET dedupe_key = 'legacy:' || md5(title)
        WHERE dedupe_key IS NULL
    """)

    # 2. Create finding_events table.
    op.create_table(
        "finding_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 3. Create org_sla_config table.
    op.create_table(
        "org_sla_config",
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("critical_days", sa.Integer(), server_default="7", nullable=False),
        sa.Column("high_days", sa.Integer(), server_default="14", nullable=False),
        sa.Column("medium_days", sa.Integer(), server_default="30", nullable=False),
        sa.Column("low_days", sa.Integer(), server_default="90", nullable=False),
    )

    # 4. Create scan_module_runs table.
    op.create_table(
        "scan_module_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scan_history.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("module", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 5. Merge duplicate findings: keep the row with the newest updated_at
    # (or highest id as tiebreaker).  Copy first_seen_at = MIN across group.
    # Delete the rest.
    op.execute("""
        WITH to_keep AS (
            SELECT DISTINCT ON (organization_id, asset_id, dedupe_key)
                id
            FROM findings
            ORDER BY organization_id, asset_id, dedupe_key,
                     updated_at DESC NULLS LAST, id DESC
        )
        UPDATE findings SET
            first_seen_at = sub.min_first
        FROM (
            SELECT organization_id, asset_id, dedupe_key,
                   MIN(first_seen_at) AS min_first
            FROM findings
            GROUP BY organization_id, asset_id, dedupe_key
            HAVING COUNT(*) > 1
        ) sub
        WHERE findings.id IN (SELECT id FROM to_keep)
          AND findings.organization_id = sub.organization_id
          AND findings.asset_id = sub.asset_id
          AND findings.dedupe_key = sub.dedupe_key
    """)
    op.execute("""
        DELETE FROM findings
        WHERE id NOT IN (
            SELECT id FROM (
                SELECT DISTINCT ON (organization_id, asset_id, dedupe_key)
                    id
                FROM findings
                ORDER BY organization_id, asset_id, dedupe_key,
                         updated_at DESC NULLS LAST, id DESC
            ) keepers
        )
    """)

    # 6. Add NOT NULL for dedupe_key and first_seen_at.
    op.execute("UPDATE findings SET dedupe_key = 'legacy:' || md5(title) WHERE dedupe_key IS NULL")
    op.execute("UPDATE findings SET first_seen_at = created_at WHERE first_seen_at IS NULL")
    op.alter_column("findings", "dedupe_key", nullable=False)
    op.alter_column("findings", "first_seen_at", nullable=False)

    # 7. Add unique index (CONCURRENTLY for production; standard in tests).
    op.create_index(
        "uq_findings_org_asset_dedupe",
        "findings",
        ["organization_id", "asset_id", "dedupe_key"],
        unique=True,
    )

    # 8. Add (organization_id, status), (organization_id, assigned_to), due_date indexes.
    op.create_index("ix_findings_org_status", "findings", ["organization_id", "status"])
    op.create_index("ix_findings_org_assigned", "findings", ["organization_id", "assigned_to"])
    op.create_index("ix_findings_due_date", "findings", ["due_date"])

    # 7. Backfill SLA due_dates (baseline: no alerts for pre-existing).
    op.execute("""
        UPDATE findings SET due_date = first_seen_at + INTERVAL '7 days'
        WHERE severity = 'critical' AND due_date IS NULL
    """)
    op.execute("""
        UPDATE findings SET due_date = first_seen_at + INTERVAL '14 days'
        WHERE severity = 'high' AND due_date IS NULL
    """)
    op.execute("""
        UPDATE findings SET due_date = first_seen_at + INTERVAL '30 days'
        WHERE severity = 'medium' AND due_date IS NULL
    """)
    op.execute("""
        UPDATE findings SET due_date = first_seen_at + INTERVAL '90 days'
        WHERE severity = 'low' AND due_date IS NULL
    """)
    # Baseline sla_alerted_at so pre-existing breaches don't alert.
    op.execute("UPDATE findings SET sla_alerted_at = now() WHERE sla_alerted_at IS NULL")

    # 8. Add FK constraints.
    op.create_foreign_key(
        "fk_findings_assigned_to", "findings", "users",
        ["assigned_to"], ["id"], ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_findings_resolved_by", "findings", "users",
        ["resolved_by"], ["id"], ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_findings_suppressed_by", "findings", "users",
        ["suppressed_by"], ["id"], ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_findings_last_seen_scan", "findings", "scan_history",
        ["last_seen_scan_id"], ["id"], ondelete="SET NULL",
    )


def downgrade() -> None:
    # Note: cannot restore merged duplicates.
    op.drop_constraint("fk_findings_last_seen_scan", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_suppressed_by", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_resolved_by", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_assigned_to", "findings", type_="foreignkey")
    op.drop_index("ix_findings_due_date", table_name="findings")
    op.drop_index("ix_findings_org_assigned", table_name="findings")
    op.drop_index("ix_findings_org_status", table_name="findings")
    op.drop_index("uq_findings_org_asset_dedupe", table_name="findings")
    op.drop_table("scan_module_runs")
    op.drop_table("org_sla_config")
    op.drop_table("finding_events")
    op.drop_column("findings", "sla_alerted_at")
    op.drop_column("findings", "suppressed_until")
    op.drop_column("findings", "suppressed_by")
    op.drop_column("findings", "suppression_reason")
    op.drop_column("findings", "resolved_by")
    op.drop_column("findings", "resolved_at")
    op.drop_column("findings", "due_date")
    op.drop_column("findings", "assigned_to")
    op.drop_column("findings", "status")
    op.drop_column("findings", "version")
    op.drop_column("findings", "last_seen_scan_id")
    op.drop_column("findings", "last_seen_at")
    op.drop_column("findings", "first_seen_at")
    op.drop_column("findings", "target_host")
    op.drop_column("findings", "source_module")
