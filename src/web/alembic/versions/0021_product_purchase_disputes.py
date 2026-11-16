"""Per-dispute amount + outcome records for product purchases.

Remediation5 (issue #164 Phase A, PR #172): a charge can carry
several disputes, but ``product_purchases.disputed_cents`` holds
only the latest dispute event's amount, so reconciliation's
ledger side under-deducted whenever a purchase had more than one
lost dispute (or a won dispute arrived after a lost one).
``product_purchase_disputes`` persists amount + latest status per
Stripe dispute ID (unique — upserts are idempotent across
created/closed events and redeliveries); reconciliation sums the
lost disputes' amounts under the unrefunded-remainder cap.

down_revision points at the SHORTENED 0020 revision id
("0020_disputed_charge_anchor", remediation5 fix 3): the original
0020 id was 39 chars and overflowed alembic_version.version_num
varchar(32) on PostgreSQL.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0021_product_purchase_disputes"
down_revision = "0020_disputed_charge_anchor"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "product_purchase_disputes",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("product_purchase_id", UUID_TYPE,
                  sa.ForeignKey("product_purchases.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("stripe_dispute_id", sa.String(255), nullable=False, unique=True),
        sa.Column("amount_cents", sa.Integer, nullable=True),
        sa.Column("status", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_product_purchase_disputes_product_purchase_id",
                    "product_purchase_disputes", ["product_purchase_id"])


def downgrade():
    op.drop_index("ix_product_purchase_disputes_product_purchase_id",
                  table_name="product_purchase_disputes")
    op.drop_table("product_purchase_disputes")
