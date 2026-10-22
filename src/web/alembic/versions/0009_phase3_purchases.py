"""Phase 3 purchase settlement tables (issue #69).

credit_purchases: one row per checkout attempt, created 'pending' before the
Stripe session exists; the webhook transitions pending -> completed.
stripe_webhook_events: append-only delivery log; the PK on stripe_event_id
is the replay-idempotency guard.

Also wires the anticipated FK credit_grants.purchase_id -> credit_purchases.id
(the column already exists, nullable).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0009_phase3_purchases"
down_revision = "0008_notify_signups"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "credit_purchases",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("stripe_session_id", sa.String(255), unique=True, nullable=True),
        sa.Column("stripe_payment_intent_id", sa.String(255), nullable=True),
        sa.Column("pack_id", sa.String(20), nullable=False),
        sa.Column("credits", sa.Integer, nullable=False),
        sa.Column("amount_cents", sa.Integer, nullable=True),
        sa.Column("currency", sa.String(10), nullable=True),
        sa.Column("pricing_version", sa.Integer, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("stripe_event_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("credits > 0", name="ck_purchase_credits_positive"),
        sa.CheckConstraint("status IN ('pending','completed','failed')",
                           name="ck_purchase_status_valid"),
        sa.CheckConstraint(
            "(status != 'completed') OR (amount_cents IS NOT NULL AND amount_cents > 0)",
            name="ck_purchase_completed_has_amount",
        ),
    )
    op.create_table(
        "stripe_webhook_events",
        sa.Column("stripe_event_id", sa.String(255), primary_key=True),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("purchase_id", UUID_TYPE, sa.ForeignKey("credit_purchases.id"),
                  nullable=True),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("note", sa.String(255), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('processed','duplicate','ignored','failed')",
            name="ck_webhook_event_outcome_valid",
        ),
    )
    # Batch mode: SQLite cannot ALTER-add a constraint; batch recreates the
    # table (copy-and-move). Postgres applies the ALTER directly.
    with op.batch_alter_table("credit_grants") as batch_op:
        batch_op.create_foreign_key(
            "fk_grant_purchase_id", "credit_purchases",
            ["purchase_id"], ["id"],
        )


def downgrade():
    with op.batch_alter_table("credit_grants") as batch_op:
        batch_op.drop_constraint("fk_grant_purchase_id", type_="foreignkey")
    op.drop_table("stripe_webhook_events")
    op.drop_table("credit_purchases")
