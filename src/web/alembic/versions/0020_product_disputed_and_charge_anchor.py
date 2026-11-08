"""Persisted dispute amount + Stripe charge creation anchor.

Remediation4 (issue #164 Phase A, PR #172):

``product_purchases.disputed_cents`` records the amount of the
dispute Stripe reported, so reconciliation's ledger-side
lost-dispute deduction can be ``min(disputed_cents, amount -
refunded)`` — mirroring the Stripe side's per-charge cap — instead
of always deducting the full unrefunded remainder for a partial
lost dispute. Legacy rows keep NULL and the full-remainder
fallback.

``product_purchases.stripe_charge_created_at`` records the Stripe
charge creation timestamp at settlement (from the completed
session object's ``created``), the shared anchor reconciliation
buckets product gross and reversal membership by, so delayed /
cross-midnight settlement agrees with the Stripe charge fetch
(which keys on charge creation time) on both sides. Legacy rows
keep NULL and fall back to ``completed_at``.
"""
import sqlalchemy as sa
from alembic import op

revision = "0020_product_disputed_and_charge_anchor"
down_revision = "0019_product_reversal_fields"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("product_purchases") as batch:
        batch.add_column(sa.Column("disputed_cents", sa.Integer, nullable=True))
        batch.add_column(sa.Column("stripe_charge_created_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table("product_purchases") as batch:
        batch.drop_column("stripe_charge_created_at")
        batch.drop_column("disputed_cents")
