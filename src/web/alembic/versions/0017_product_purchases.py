"""Per-product dollar purchases + entitlements (issue #164 Phase A).

New generic tables (product_purchases, entitlements,
entitlement_redemptions); legacy credit tables untouched. Results gain
the third origin (A2); the webhook log gains the product FK with an
at-most-one-purchase check (A3); reconciliation gains the family
dimension (A8, schema_version 2).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0017_product_purchases"
down_revision = "0016_report_branding"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "product_purchases",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE,
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sku", sa.String(40), nullable=False),
        sa.Column("source_result_id", UUID_TYPE,
                  sa.ForeignKey("results.id"), nullable=False),
        sa.Column("stripe_session_id", sa.String(255), nullable=True, unique=True),
        sa.Column("stripe_payment_intent_id", sa.String(255), nullable=True),
        sa.Column("amount_cents", sa.Integer, nullable=True),
        sa.Column("currency", sa.String(10), nullable=True),
        sa.Column("stripe_price_id", sa.String(255), nullable=True),
        sa.Column("pricing_version", sa.Integer, nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("stripe_event_id", sa.String(255), nullable=True),
        sa.Column("reversal_event_id", sa.String(255), nullable=True),
        sa.Column("reversal_kind", sa.String(20), nullable=True),
        sa.Column("reversed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("needs_manual_review", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','completed','failed','refunded','disputed')",
            name="ck_product_purchase_status_valid"),
        sa.CheckConstraint(
            "(status != 'completed') OR (amount_cents IS NOT NULL AND amount_cents > 0)",
            name="ck_product_purchase_completed_has_amount"),
    )
    op.create_index("ix_product_purchases_user_id", "product_purchases", ["user_id"])
    # P2-4: index names must match the models' conventional
    # ix_<table>_<column> names exactly, or compare_metadata diffs.
    op.create_index("ix_product_purchases_source_result_id", "product_purchases", ["source_result_id"])
    op.create_index("ix_product_purchases_pending_unique", "product_purchases",
                    ["user_id", "source_result_id", "sku"], unique=True,
                    postgresql_where=sa.text("status = 'pending'"),
                    sqlite_where=sa.text("status = 'pending'"))

    op.create_table(
        "entitlements",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE,
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_purchase_id", UUID_TYPE,
                  sa.ForeignKey("product_purchases.id"), nullable=False, unique=True),
        sa.Column("sku", sa.String(40), nullable=False),
        sa.Column("source_result_id", UUID_TYPE,
                  sa.ForeignKey("results.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("redemption_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("redeemed_result_id", UUID_TYPE,
                  sa.ForeignKey("results.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('available','reserved','redeemed','revoked','refund_eligible')",
            name="ck_entitlement_status_valid"),
    )
    op.create_index("ix_entitlements_user_id", "entitlements", ["user_id"])
    op.create_index("ix_entitlements_source_result_id", "entitlements", ["source_result_id"])
    op.create_index("ix_entitlements_live_unique", "entitlements",
                    ["user_id", "source_result_id", "sku"], unique=True,
                    postgresql_where=sa.text("status IN ('available', 'reserved')"),
                    sqlite_where=sa.text("status IN ('available', 'reserved')"))

    op.create_table(
        "entitlement_redemptions",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("entitlement_id", UUID_TYPE,
                  sa.ForeignKey("entitlements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_result_id", UUID_TYPE,
                  sa.ForeignKey("results.id"), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("worker_id", sa.String(255), nullable=False),
        sa.Column("lease_generation", sa.Integer, nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("failure_code", sa.String(50), nullable=True),
        sa.Column("result_id", UUID_TYPE,
                  sa.ForeignKey("results.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('reserved','completed','released','stopped')",
            name="ck_redemption_status_valid"),
    )
    op.create_index("ix_entitlement_redemptions_entitlement_id",
                    "entitlement_redemptions", ["entitlement_id"])
    op.create_index("ix_redemption_entitlement_live", "entitlement_redemptions",
                    ["entitlement_id"], unique=True,
                    postgresql_where=sa.text("status = 'reserved'"),
                    sqlite_where=sa.text("status = 'reserved'"))

    with op.batch_alter_table("results") as batch:
        batch.add_column(sa.Column(
            "product_redemption_id", UUID_TYPE, nullable=True))
        batch.create_foreign_key(
            "fk_results_product_redemption_id", "entitlement_redemptions",
            ["product_redemption_id"], ["id"])
        batch.create_unique_constraint(
            "uq_results_product_redemption_id", ["product_redemption_id"])
        batch.drop_constraint("ck_result_exactly_one_origin", type_="check")
        batch.create_check_constraint(
            "ck_result_exactly_one_origin",
            "(CASE WHEN operation_id IS NOT NULL THEN 1 ELSE 0 END)"
            " + (CASE WHEN free_request_id IS NOT NULL THEN 1 ELSE 0 END)"
            " + (CASE WHEN product_redemption_id IS NOT NULL THEN 1 ELSE 0 END)"
            " = 1")

    with op.batch_alter_table("stripe_webhook_events") as batch:
        batch.add_column(sa.Column(
            "product_purchase_id", UUID_TYPE, nullable=True))
        batch.create_foreign_key(
            "fk_webhook_product_purchase_id", "product_purchases",
            ["product_purchase_id"], ["id"])
        batch.add_column(sa.Column("attempts", sa.Integer, nullable=False,
                                   server_default="1"))
        batch.create_check_constraint(
            "ck_webhook_event_at_most_one_purchase",
            "(purchase_id IS NULL) OR (product_purchase_id IS NULL)")

    with op.batch_alter_table("payment_reconciliations") as batch:
        batch.add_column(sa.Column("schema_version", sa.Integer,
                                   nullable=False, server_default="1"))
        batch.add_column(sa.Column("per_family", sa.JSON, nullable=True))


def downgrade():
    with op.batch_alter_table("payment_reconciliations") as batch:
        batch.drop_column("per_family")
        batch.drop_column("schema_version")
    with op.batch_alter_table("stripe_webhook_events") as batch:
        batch.drop_constraint("ck_webhook_event_at_most_one_purchase", type_="check")
        batch.drop_constraint("fk_webhook_product_purchase_id", type_="foreignkey")
        batch.drop_column("attempts")
        batch.drop_column("product_purchase_id")
    with op.batch_alter_table("results") as batch:
        batch.drop_constraint("ck_result_exactly_one_origin", type_="check")
        batch.create_check_constraint(
            "ck_result_exactly_one_origin",
            "(operation_id IS NOT NULL) <> (free_request_id IS NOT NULL)")
        batch.drop_constraint("uq_results_product_redemption_id", type_="unique")
        batch.drop_constraint("fk_results_product_redemption_id", type_="foreignkey")
        batch.drop_column("product_redemption_id")
    op.drop_table("entitlement_redemptions")
    op.drop_table("entitlements")
    op.drop_table("product_purchases")
