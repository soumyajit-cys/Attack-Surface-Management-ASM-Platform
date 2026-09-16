"""add jira connector columns to alert integrations

Revision ID: 9f3c7e2b1a5d
Revises: 7d2b1f0a4c9e
Create Date: 2026-09-16

Native Jira support: ``webhook_url`` becomes nullable (Jira uses a REST
base URL + API token instead of a webhook) and Jira connection fields are
added. Existing slack/discord rows are unaffected.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '9f3c7e2b1a5d'
down_revision: Union[str, None] = '7d2b1f0a4c9e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('alert_integrations', 'webhook_url',
                    existing_type=sa.String(), nullable=True)
    op.add_column('alert_integrations', sa.Column('jira_base_url', sa.String(), nullable=True))
    op.add_column('alert_integrations', sa.Column('jira_project_key', sa.String(), nullable=True))
    op.add_column('alert_integrations', sa.Column('jira_email', sa.String(), nullable=True))
    op.add_column('alert_integrations', sa.Column('jira_api_token', sa.String(), nullable=True))
    op.add_column('alert_integrations', sa.Column('jira_issue_type', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('alert_integrations', 'jira_issue_type')
    op.drop_column('alert_integrations', 'jira_api_token')
    op.drop_column('alert_integrations', 'jira_email')
    op.drop_column('alert_integrations', 'jira_project_key')
    op.drop_column('alert_integrations', 'jira_base_url')
    op.alter_column('alert_integrations', 'webhook_url',
                    existing_type=sa.String(), nullable=False)
