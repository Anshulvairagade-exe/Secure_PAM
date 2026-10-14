"""risk_findings for the Risk Centre

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-10-15 02:00:00

Additive only: one new table. Downgrade drops it.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'risk_findings',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('fingerprint', sa.String(length=128), nullable=False),
        sa.Column('rule_code', sa.String(length=64), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=10), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('subject', sa.String(length=255), nullable=False),
        sa.Column('asset_id', sa.UUID(), nullable=True),
        sa.Column('application_id', sa.UUID(), nullable=True),
        sa.Column('user_id', sa.UUID(), nullable=True),
        sa.Column('session_id', sa.UUID(), nullable=True),
        sa.Column('evidence', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('remediation', sa.Text(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('occurrences', sa.Integer(), nullable=False),
        sa.Column('status_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status_changed_by', sa.UUID(), nullable=True),
        sa.Column('status_note', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['status_changed_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_risk_findings_fingerprint', 'risk_findings', ['fingerprint'], unique=True)
    for col in ('rule_code', 'source', 'severity', 'status', 'asset_id', 'application_id', 'user_id',
                'first_seen', 'last_seen'):
        op.create_index(f'ix_risk_findings_{col}', 'risk_findings', [col])


def downgrade() -> None:
    op.drop_table('risk_findings')
