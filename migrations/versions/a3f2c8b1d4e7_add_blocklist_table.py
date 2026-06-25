"""add_blocklist_table

Revision ID: a3f2c8b1d4e7
Revises: cac15525a8d8
Create Date: 2026-06-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3f2c8b1d4e7'
down_revision: Union[str, Sequence[str], None] = 'cac15525a8d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'blocklist',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('entry_type', sa.String(length=16), nullable=False),
        sa.Column('value', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('entry_type', 'value', name='uq_blocklist_type_value'),
    )
    with op.batch_alter_table('blocklist', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_blocklist_entry_type'), ['entry_type'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('blocklist', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_blocklist_entry_type'))
    op.drop_table('blocklist')
