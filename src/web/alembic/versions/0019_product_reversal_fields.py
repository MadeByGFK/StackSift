"""Dedicated product reversal accounting fields.

Remediation3 (issue #164 Phase A, PR #172 findings 3+5):
``apply_dispute`` overwrote ``reversal_kind``/``reversed_at``
unconditionally, so a partially refunded purchase that later saw a
dispute event dropped out of reconciliation's refund query and its
refund deduction vanished; both product reversal queries also
bucketed by ``reversed_at`` (processing day) while the Stripe side
attributes refunds/disputes to the charge's creation day.

``product_purchases.refunded_at`` (processing time of the refund
event that set the current maximum cumulative ``refunded_cents``)
and ``product_purchases.dispute_lost_at`` (a dispute was lost, ever)
give reconciliation dedicated fields that later reversal events
cannot erase or move. Entitlement semantics (F3) are unchanged.
"""
import sqlalchemy as sa
from alembic import op

revision = "0019_product_reversal_fields"
down_revision = "0018_product_refunded_cents"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("product_purchases") as batch:
        batch.add_column(sa.Column("refunded_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("dispute_lost_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table("product_purchases") as batch:
        batch.drop_column("dispute_lost_at")
        batch.drop_column("refunded_at")
