"""adding new fields to User and adding change logging

Revision ID: d1ad681bb005
Revises: 15f470aeceb6
Create Date: 2023-03-21 19:51:03.974537

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd1ad681bb005'
down_revision = '15f470aeceb6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('system_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('event_code', sa.Integer(), nullable=True),
    sa.Column('event_time', sa.DateTime(), nullable=True),
    sa.Column('event_desc', sa.String(length=256), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_change',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('change_code', sa.Integer(), nullable=True),
    sa.Column('change_time', sa.DateTime(), nullable=True),
    sa.Column('change_desc', sa.String(length=256), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('card_image_url', sa.String(length=1000), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('card_image_url')

    op.drop_table('user_change')
    op.drop_table('system_log')
    # ### end Alembic commands ###
