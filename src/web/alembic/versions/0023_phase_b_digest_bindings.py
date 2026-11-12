"""Phase B digest bindings + billing-mode constraints (issue #164).

B-5a: product_purchases / entitlements / entitlement_redemptions gain
a nullable ``content_digest`` and a nullable ``source_result_id``,
with a CHECK that exactly one binding is set, plus digest partial
unique indexes mirroring the source-bound F1 backstops (B-10).
B-7: consents gain ``sku`` and the cost CHECK becomes billing-mode
aware. B-8/B-16: operations gain ``entitlement_redemption_id`` and
the cost CHECK becomes billing-mode aware.
"""
import sqlalchemy as sa
from alembic import op

revision = "0023_phase_b_digest_bindings"
down_revision = "0022_report_ss_id"
branch_labels = None
depends_on = None


def upgrade():
    # --- product_purchases -------------------------------------------
    with op.batch_alter_table("product_purchases") as batch_op:
        batch_op.add_column(sa.Column("content_digest", sa.String(64), nullable=True))
        batch_op.alter_column("source_result_id", existing_type=sa.String(36),
                              nullable=True)
        batch_op.create_check_constraint(
            "ck_product_purchase_exactly_one_binding",
            "(source_result_id IS NOT NULL) <> (content_digest IS NOT NULL)")
    op.create_index("ix_product_purchases_content_digest",
                    "product_purchases", ["content_digest"])
    op.create_index(
        "ix_product_purchases_pending_digest_unique", "product_purchases",
        ["user_id", "sku", "content_digest"], unique=True,
        postgresql_where=sa.text("status = 'pending' AND content_digest IS NOT NULL"),
        sqlite_where=sa.text("status = 'pending' AND content_digest IS NOT NULL"))

    # --- entitlements --------------------------------------------------
    with op.batch_alter_table("entitlements") as batch_op:
        batch_op.add_column(sa.Column("content_digest", sa.String(64), nullable=True))
        batch_op.alter_column("source_result_id", existing_type=sa.String(36),
                              nullable=True)
        batch_op.create_check_constraint(
            "ck_entitlement_exactly_one_binding",
            "(source_result_id IS NOT NULL) <> (content_digest IS NOT NULL)")
    op.create_index("ix_entitlements_content_digest",
                    "entitlements", ["content_digest"])
    op.create_index(
        "ix_entitlements_live_digest_unique", "entitlements",
        ["user_id", "sku", "content_digest"], unique=True,
        postgresql_where=sa.text(
            "status IN ('available', 'reserved') AND content_digest IS NOT NULL"),
        sqlite_where=sa.text(
            "status IN ('available', 'reserved') AND content_digest IS NOT NULL"))

    # --- entitlement_redemptions ---------------------------------------
    with op.batch_alter_table("entitlement_redemptions") as batch_op:
        batch_op.add_column(sa.Column("content_digest", sa.String(64), nullable=True))
        batch_op.alter_column("source_result_id", existing_type=sa.String(36),
                              nullable=True)

    # --- consents (B-7) -------------------------------------------------
    # NOT batch_alter_table: batch recreation rewrites consents'
    # column-level FK on consumed_by_free_request_id as a table-level
    # FK, and SQLite cannot DROP COLUMN a table-level-FK column —
    # migration 0004's downgrade (plain drop_column) would break.
    op.add_column("consents", sa.Column("sku", sa.String(40), nullable=True))
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("ck_consent_max_cost_positive", "consents",
                           type_="check")
        op.create_check_constraint(
            "ck_consent_cost_matches_billing_mode", "consents",
            "(sku IS NULL AND max_cost > 0) OR (sku IS NOT NULL AND max_cost = 0)")
    # On SQLite the legacy positive-cost CHECK stays in migrated
    # schemas; the billing-mode invariant is enforced by the model
    # CHECK on create_all databases and by validate_consent in code.

    # --- operations (B-8/B-16) ------------------------------------------
    with op.batch_alter_table("operations") as batch_op:
        batch_op.add_column(sa.Column(
            "entitlement_redemption_id", sa.String(36),
            sa.ForeignKey("entitlement_redemptions.id",
                          name="fk_operations_entitlement_redemption_id"),
            nullable=True))
        batch_op.create_unique_constraint(
            "uq_operations_entitlement_redemption_id",
            ["entitlement_redemption_id"])
        batch_op.drop_constraint("ck_operation_cost_positive", type_="check")
        batch_op.create_check_constraint(
            "ck_operation_cost_matches_billing_mode",
            "(entitlement_redemption_id IS NULL AND cost > 0) OR "
            "(entitlement_redemption_id IS NOT NULL AND cost = 0)")


def downgrade():
    with op.batch_alter_table("operations") as batch_op:
        batch_op.drop_constraint("ck_operation_cost_matches_billing_mode",
                                 type_="check")
        batch_op.create_check_constraint("ck_operation_cost_positive", "cost > 0")
        batch_op.drop_constraint("uq_operations_entitlement_redemption_id",
                                 type_="unique")
        batch_op.drop_column("entitlement_redemption_id")
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("ck_consent_cost_matches_billing_mode",
                           "consents", type_="check")
        op.create_check_constraint("ck_consent_max_cost_positive",
                                   "consents", "max_cost > 0")
    op.drop_column("consents", "sku")
    with op.batch_alter_table("entitlement_redemptions") as batch_op:
        batch_op.alter_column("source_result_id", existing_type=sa.String(36),
                              nullable=False)
        batch_op.drop_column("content_digest")
    op.drop_index("ix_entitlements_live_digest_unique", table_name="entitlements")
    op.drop_index("ix_entitlements_content_digest", table_name="entitlements")
    with op.batch_alter_table("entitlements") as batch_op:
        batch_op.drop_constraint("ck_entitlement_exactly_one_binding",
                                 type_="check")
        batch_op.alter_column("source_result_id", existing_type=sa.String(36),
                              nullable=False)
        batch_op.drop_column("content_digest")
    op.drop_index("ix_product_purchases_pending_digest_unique",
                  table_name="product_purchases")
    op.drop_index("ix_product_purchases_content_digest",
                  table_name="product_purchases")
    with op.batch_alter_table("product_purchases") as batch_op:
        batch_op.drop_constraint("ck_product_purchase_exactly_one_binding",
                                 type_="check")
        batch_op.alter_column("source_result_id", existing_type=sa.String(36),
                              nullable=False)
        batch_op.drop_column("content_digest")
