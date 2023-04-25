"""adding view_count and post_view_count to User

Revision ID: d58e72cb0cbf
Revises: e105d1383e07
Create Date: 2023-04-24 20:46:55.820950

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd58e72cb0cbf'
down_revision = 'e105d1383e07'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('post_view_count', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('post_view_count')

    # ### end Alembic commands ###
