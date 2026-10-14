"""application start_path and tls_pin_sha256 for isolated browser sessions

Revision ID: c3d4e5f6a7b8
Revises: b7c1d2e3f4a5
Create Date: 2026-10-14 20:00:00

Additive only. Existing applications start at "/" with normal certificate validation.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b7c1d2e3f4a5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('applications', sa.Column('start_path', sa.String(length=512), server_default='/', nullable=False,
                                            comment='Path on the registered origin the isolated browser opens'))
    op.add_column('applications', sa.Column('tls_pin_sha256', sa.String(length=64), nullable=True,
                                            comment='Pinned server key (base64 SHA-256 of SPKI) for an explicitly trusted certificate'))


def downgrade() -> None:
    op.drop_column('applications', 'tls_pin_sha256')
    op.drop_column('applications', 'start_path')
