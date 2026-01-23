"""add transfer_orders

Revision ID: 8eea8494a474
Revises: 2a424799bdd7
Create Date: 2026-01-20 21:42:04.150940

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '8eea8494a474'
down_revision = '2a424799bdd7'
branch_labels = None
depends_on = None

def upgrade():
    # ✅ Cambio seguro: solo agregar columna nueva
    op.add_column("transfer_orders", sa.Column("amount_cents", sa.Integer(), nullable=True))

    # (Opcional) Si tu tabla aún tiene amount_mxn y quieres rellenar amount_cents:
    op.execute("UPDATE transfer_orders SET amount_cents = ROUND(amount_mxn * 100)::int "
               "WHERE amount_cents IS NULL AND amount_mxn IS NOT NULL")


def downgrade():
    op.drop_column("transfer_orders", "amount_cents")