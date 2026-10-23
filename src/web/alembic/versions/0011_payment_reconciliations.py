"""Daily Stripe-to-ledger reconciliation records (issue #72).

payment_reconciliations: one row per UTC calendar day with per-pack
Stripe-vs-ledger totals (to the cent), the identified differences on a
mismatch, and the founder-alert delivery state.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0011_payment_reconciliations"
down_revision = "0010_merge_heads"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "payment_reconciliations",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("recon_date", sa.Date, nullable=False, unique=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("stripe_gross_cents", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("stripe_refund_cents", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("stripe_dispute_cents", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("ledger_gross_cents", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("ledger_refund_cents", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("per_pack", sa.JSON, nullable=True),
        sa.Column("differences", sa.JSON, nullable=True),
        sa.Column("alert_sent", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("alert_pending", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("error_note", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('clean','mismatch','error','skipped')",
            name="ck_recon_status_valid",
        ),
    )


def downgrade():
    op.drop_table("payment_reconciliations")
