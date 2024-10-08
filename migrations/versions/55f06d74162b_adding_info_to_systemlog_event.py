"""Adding info to systemlog event

Revision ID: 55f06d74162b
Revises: a2fda4a9c527
Create Date: 2023-04-23 23:55:09.582554

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '55f06d74162b'
down_revision = 'a2fda4a9c527'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('system_log', schema=None) as batch_op:
        batch_op.add_column(sa.Column('referrer', sa.String(length=256), nullable=True))
        batch_op.add_column(sa.Column('user_agent', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('remote_addr', sa.String(length=256), nullable=True))
        batch_op.add_column(sa.Column('endpoint', sa.String(length=128), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('system_log', schema=None) as batch_op:
        batch_op.drop_column('endpoint')
        batch_op.drop_column('remote_addr')
        batch_op.drop_column('user_agent')
        batch_op.drop_column('referrer')

    # ### end Alembic commands ###
