"""Dashboard upgrade migration

Revision ID: 001_dashboard_upgrade
Revises: 
Create Date: 2026-10-31 22:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision: str = '001_dashboard_upgrade'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    insp = inspect(conn)
    tables = insp.get_table_names()

    # 1. Applications table
    if 'applications' not in tables:
        op.create_table(
            'applications',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('name', sa.String(), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_applications_name', 'applications', ['name'])

    # 2. Targets columns
    target_cols = {col['name'] for col in insp.get_columns('targets')} if 'targets' in tables else set()
    if 'application_id' not in target_cols:
        op.add_column('targets', sa.Column('application_id', sa.String(), nullable=True))
        try:
            op.create_foreign_key('fk_targets_application', 'targets', 'applications', ['application_id'], ['id'], ondelete='SET NULL')
        except Exception:
            pass
        op.create_index('ix_targets_application_id', 'targets', ['application_id'])
    if 'name' not in target_cols:
        op.add_column('targets', sa.Column('name', sa.String(), nullable=True))

    # 3. Scans columns
    scan_cols = {col['name'] for col in insp.get_columns('scans')} if 'scans' in tables else set()
    if 'application_id' not in scan_cols:
        op.add_column('scans', sa.Column('application_id', sa.String(), nullable=True))
        try:
            op.create_foreign_key('fk_scans_application', 'scans', 'applications', ['application_id'], ['id'], ondelete='SET NULL')
        except Exception:
            pass
        op.create_index('ix_scans_application_id', 'scans', ['application_id'])
    if 'enable_browser_discovery' not in scan_cols:
        op.add_column('scans', sa.Column('enable_browser_discovery', sa.Boolean(), server_default='true', nullable=True))
    if 'route_summary' not in scan_cols:
        op.add_column('scans', sa.Column('route_summary', sa.JSON(), nullable=True))

    # 4. Findings columns
    finding_cols = {col['name'] for col in insp.get_columns('findings')} if 'findings' in tables else set()
    if 'status' not in finding_cols:
        op.add_column('findings', sa.Column('status', sa.String(), server_default='open', nullable=True))
        op.create_index('ix_findings_status', 'findings', ['status'])
    if 'fingerprint' not in finding_cols:
        op.add_column('findings', sa.Column('fingerprint', sa.String(), nullable=True))
        op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'])
    if 'status_note' not in finding_cols:
        op.add_column('findings', sa.Column('status_note', sa.Text(), nullable=True))
    if 'status_updated_at' not in finding_cols:
        op.add_column('findings', sa.Column('status_updated_at', sa.DateTime(), nullable=True))

    # 5. Activities table
    if 'activities' not in tables:
        op.create_table(
            'activities',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('scan_id', sa.String(), sa.ForeignKey('scans.id', ondelete='SET NULL'), nullable=True),
            sa.Column('application_id', sa.String(), sa.ForeignKey('applications.id', ondelete='SET NULL'), nullable=True),
            sa.Column('event_type', sa.String(), nullable=False),
            sa.Column('title', sa.String(), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('severity', sa.String(), server_default='info', nullable=True),
            sa.Column('timestamp', sa.DateTime(), nullable=True),
            sa.Column('metadata', sa.JSON(), nullable=True),
        )
        op.create_index('ix_activities_timestamp', 'activities', ['timestamp'])
        op.create_index('ix_activities_event_type', 'activities', ['event_type'])


def downgrade() -> None:
    pass

