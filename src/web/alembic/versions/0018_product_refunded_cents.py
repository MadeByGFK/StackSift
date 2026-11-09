"""Persist cumulative refunded cents on product purchases.

Remediation2 P2-C (issue #164 Phase A): a partial refund previously
recorded only reversal provenance (kind/event/timestamp), so the
reconciliation ledger side excluded the partial amount while the
Stripe charge side subtracted amount_refunded — a permanent false
mismatch. ``product_purchases.refunded_cents`` stores the latest
cumulative refunded amount; entitlement semantics (F3: a partial
refund never degrades the entitlement) are unchanged.
"""
import sqlalchemy as sa
from alembic import op

revision = "0018_product_refunded_cents"
down_revision = "0017_product_purchases"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("product_purchases") as batch:
        batch.add_column(sa.Column("refunded_cents", sa.Integer, nullable=True))


def downgrade():
    with op.batch_alter_table("product_purchases") as batch:
        batch.drop_column("refunded_cents")
