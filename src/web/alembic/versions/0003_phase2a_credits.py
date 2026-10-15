"""Phase 2A: Power-Up credits — accounting, operations, admission.

Tables: credit_accounts, credit_grants, credit_ledger, ledger_grants,
operations, operation_allocations, results, consents, admin_adjustments,
signup_eligibility, capacity_scopes, permits, permit_scopes, rate_buckets,
free_buckets, free_requests, restrictions.

Phase 3 tables (purchases, checkout_attempts, external_requests, refunds,
provider_events, payment_disputes, etc.) are NOT included.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0003_phase2a_credits"
down_revision = "0002_oauth_state"
branch_labels = None
depends_on = None


def _add_fk(table, constraint_name, ref_table, local_cols, remote_cols):
    """Add FK with batch mode on SQLite (which lacks ALTER ADD CONSTRAINT)."""
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(table) as batch_op:
            batch_op.create_foreign_key(constraint_name, ref_table, local_cols, remote_cols)
    else:
        op.create_foreign_key(constraint_name, table, ref_table, local_cols, remote_cols)


def upgrade() -> None:
    # --- credit_accounts ---
    op.create_table(
        "credit_accounts",
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("balance", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ledger_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("balance >= 0", name="ck_credit_accounts_balance_nonneg"),
    )

    # --- credit_grants ---
    op.create_table(
        "credit_grants",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("source_key", sa.String(255), nullable=False),
        sa.Column("issued", sa.Integer(), nullable=False),
        sa.Column("remaining", sa.Integer(), nullable=False),
        sa.Column("reserved", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("purchase_id", UUID_TYPE, nullable=True),
        sa.Column("revocation_queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("issued > 0", name="ck_grant_issued_positive"),
        sa.CheckConstraint("remaining >= 0", name="ck_grant_remaining_nonneg"),
        sa.CheckConstraint("reserved >= 0", name="ck_grant_reserved_nonneg"),
        sa.CheckConstraint("reserved <= remaining", name="ck_grant_reserved_lte_remaining"),
        sa.CheckConstraint("remaining <= issued", name="ck_grant_remaining_lte_issued"),
        sa.UniqueConstraint("user_id", "source", "source_key", name="uq_grant_user_source_key"),
    )
    op.create_index("ix_credit_grants_user_id", "credit_grants", ["user_id"])
    op.execute(
        "CREATE UNIQUE INDEX ix_grant_signup_user ON credit_grants (user_id) "
        "WHERE source = 'signup'"
    )

    # --- admin_adjustments (before credit_ledger for FK) ---
    op.create_table(
        "admin_adjustments",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("target_grant_id", UUID_TYPE, sa.ForeignKey("credit_grants.id"), nullable=True),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_ref", sa.String(255), nullable=True),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("approval_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("applied_ledger_id", UUID_TYPE, nullable=True),
        sa.Column("request_key", sa.String(255), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("quantity > 0", name="ck_adjustment_quantity_positive"),
    )
    op.create_index("ix_admin_adjustments_user_id", "admin_adjustments", ["user_id"])

    # --- operations (consent_id/result_id FKs added after those tables exist) ---
    op.create_table(
        "operations",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(30), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("input_manifest", sa.Text(), nullable=True),
        sa.Column("cost", sa.Integer(), nullable=False),
        sa.Column("pricing_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("consent_id", UUID_TYPE, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="reserved"),
        sa.Column("worker_id", sa.String(255), nullable=False),
        sa.Column("lease_generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result_id", UUID_TYPE, nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_code", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("cost > 0", name="ck_operation_cost_positive"),
        sa.UniqueConstraint("user_id", "type", "idempotency_key", name="uq_operation_identity"),
    )
    op.create_index("ix_operations_user_id", "operations", ["user_id"])

    # --- consents ---
    op.create_table(
        "consents",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("operation_type", sa.String(30), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("max_cost", sa.Integer(), nullable=False),
        sa.Column("pricing_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_by_operation_id", UUID_TYPE, sa.ForeignKey("operations.id"), nullable=True, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("max_cost > 0", name="ck_consent_max_cost_positive"),
    )
    op.create_index("ix_consents_user_id", "consents", ["user_id"])
    _add_fk("operations", "fk_operations_consent_id", "consents",
            ["consent_id"], ["id"])

    # --- results ---
    op.create_table(
        "results",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("anonymous_owner_hash", sa.String(64), nullable=True),
        sa.Column("operation_id", UUID_TYPE, sa.ForeignKey("operations.id"), nullable=True, unique=True),
        sa.Column("free_request_id", sa.String(255), nullable=True, unique=True),
        sa.Column("type", sa.String(30), nullable=False),
        sa.Column("storage_manifest", sa.Text(), nullable=False),
        sa.Column("integrity_digest", sa.String(64), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "(user_id IS NOT NULL) <> (anonymous_owner_hash IS NOT NULL)",
            name="ck_result_exactly_one_owner",
        ),
        sa.CheckConstraint(
            "(operation_id IS NOT NULL) <> (free_request_id IS NOT NULL)",
            name="ck_result_exactly_one_origin",
        ),
    )
    _add_fk("operations", "fk_operations_result_id", "results",
            ["result_id"], ["id"])

    # --- credit_ledger ---
    op.create_table(
        "credit_ledger",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_key", sa.String(255), nullable=False),
        sa.Column("delta", sa.Integer(), nullable=False),
        sa.Column("balance_after", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(30), nullable=False),
        sa.Column("operation_id", UUID_TYPE, sa.ForeignKey("operations.id"), nullable=True),
        sa.Column("refund_id", UUID_TYPE, nullable=True),
        sa.Column("adjustment_id", UUID_TYPE, nullable=True),
        sa.Column("reverses_entry_id", UUID_TYPE, sa.ForeignKey("credit_ledger.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("delta != 0", name="ck_ledger_delta_nonzero"),
        sa.CheckConstraint("balance_after >= 0", name="ck_ledger_balance_nonneg"),
        sa.UniqueConstraint("user_id", "event_key", name="uq_ledger_user_event_key"),
        sa.UniqueConstraint("user_id", "account_sequence", name="uq_ledger_user_sequence"),
        sa.ForeignKeyConstraint(["adjustment_id"], ["admin_adjustments.id"],
                                name="fk_ledger_adjustment_id"),
    )
    op.create_index("ix_credit_ledger_user_id", "credit_ledger", ["user_id"])
    op.execute(
        "CREATE UNIQUE INDEX ix_ledger_reverses ON credit_ledger (reverses_entry_id) "
        "WHERE reverses_entry_id IS NOT NULL"
    )
    _add_fk("admin_adjustments", "fk_adjustments_applied_ledger", "credit_ledger",
            ["applied_ledger_id"], ["id"])

    # --- ledger_grants ---
    op.create_table(
        "ledger_grants",
        sa.Column("ledger_entry_id", UUID_TYPE, sa.ForeignKey("credit_ledger.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("grant_id", UUID_TYPE, sa.ForeignKey("credit_grants.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("signed_delta", sa.Integer(), nullable=False),
        sa.CheckConstraint("signed_delta != 0", name="ck_ledger_grant_delta_nonzero"),
    )

    # --- operation_allocations ---
    op.create_table(
        "operation_allocations",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("operation_id", UUID_TYPE, sa.ForeignKey("operations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("grant_id", UUID_TYPE, sa.ForeignKey("credit_grants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False, server_default="reserved"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("quantity > 0", name="ck_allocation_quantity_positive"),
        sa.UniqueConstraint("operation_id", "grant_id", name="uq_operation_grant"),
    )
    op.create_index("ix_operation_allocations_operation_id", "operation_allocations", ["operation_id"])

    # --- signup_eligibility ---
    op.create_table(
        "signup_eligibility",
        sa.Column("email_normalized", sa.String(255), primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("issued_grant_id", UUID_TYPE, sa.ForeignKey("credit_grants.id"), nullable=True),
        sa.Column("grant_issued", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # --- capacity_scopes ---
    op.create_table(
        "capacity_scopes",
        sa.Column("scope_key", sa.String(255), primary_key=True),
        sa.Column("used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_limit", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("used >= 0", name="ck_capacity_used_nonneg"),
        sa.CheckConstraint("max_limit > 0", name="ck_capacity_limit_positive"),
    )

    # --- permits ---
    op.create_table(
        "permits",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("operation_id", UUID_TYPE, sa.ForeignKey("operations.id", ondelete="CASCADE"),
                  nullable=False, unique=True),
        sa.Column("worker_id", sa.String(255), nullable=False),
        sa.Column("lease_generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # --- permit_scopes ---
    op.create_table(
        "permit_scopes",
        sa.Column("permit_id", UUID_TYPE, sa.ForeignKey("permits.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("scope_key", sa.String(255), sa.ForeignKey("capacity_scopes.scope_key"), primary_key=True),
        sa.Column("quantity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # --- rate_buckets ---
    op.create_table(
        "rate_buckets",
        sa.Column("policy", sa.String(50), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_limit", sa.Integer(), nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("policy", "owner", "window_start"),
        sa.CheckConstraint("attempts >= 0", name="ck_rate_attempts_nonneg"),
    )

    # --- free_buckets ---
    op.create_table(
        "free_buckets",
        sa.Column("trusted_ip", sa.String(45), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("trusted_ip", "window_start", "policy_version"),
        sa.CheckConstraint("attempts >= 0", name="ck_free_attempts_nonneg"),
    )

    # --- free_requests ---
    op.create_table(
        "free_requests",
        sa.Column("request_id", sa.String(255), primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("anonymous_session_hash", sa.String(64), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="in_progress"),
        sa.Column("quota_bucket_trusted_ip", sa.String(45), nullable=True),
        sa.Column("quota_bucket_window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_id", UUID_TYPE, sa.ForeignKey("results.id"), nullable=True),
        sa.Column("failure_code", sa.String(50), nullable=True),
        sa.Column("execution_generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "(user_id IS NOT NULL) <> (anonymous_session_hash IS NOT NULL)",
            name="ck_free_request_exactly_one_owner",
        ),
    )

    # --- restrictions ---
    op.create_table(
        "restrictions",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("cause_type", sa.String(50), nullable=False),
        sa.Column("cause_id", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("imposed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("lifted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lift_evidence", sa.Text(), nullable=True),
    )
    op.create_index("ix_restrictions_user_id", "restrictions", ["user_id"])
    op.execute(
        "CREATE UNIQUE INDEX ix_restriction_active ON restrictions "
        "(user_id, action, cause_type, cause_id) WHERE lifted_at IS NULL"
    )


def downgrade() -> None:
    # Handle circular FK between credit_ledger and admin_adjustments:
    #   credit_ledger.adjustment_id -> admin_adjustments.id
    #   admin_adjustments.applied_ledger_id -> credit_ledger.id
    # Drop both FK constraints before dropping either table.
    #
    # Also handle mutual dependencies between operations and results/consents:
    #   operations.result_id -> results.id  /  results.operation_id -> operations.id
    #   operations.consent_id -> consents.id / consents.consumed_by_operation_id -> operations.id
    # Drop the operations-side constraints so results/consents can drop first.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.drop_constraint("fk_ledger_adjustment_id", "credit_ledger", type_="foreignkey")
        op.drop_constraint("fk_adjustments_applied_ledger", "admin_adjustments", type_="foreignkey")
        op.drop_constraint("fk_operations_result_id", "operations", type_="foreignkey")
        op.drop_constraint("fk_operations_consent_id", "operations", type_="foreignkey")
    elif bind.dialect.name == "sqlite":
        with op.batch_alter_table("credit_ledger") as batch_op:
            try:
                batch_op.drop_constraint("fk_ledger_adjustment_id", type_="foreignkey")
            except Exception:
                pass
        with op.batch_alter_table("admin_adjustments") as batch_op:
            try:
                batch_op.drop_constraint("fk_adjustments_applied_ledger", type_="foreignkey")
            except Exception:
                pass
        with op.batch_alter_table("operations") as batch_op:
            try:
                batch_op.drop_constraint("fk_operations_result_id", type_="foreignkey")
            except Exception:
                pass
            try:
                batch_op.drop_constraint("fk_operations_consent_id", type_="foreignkey")
            except Exception:
                pass

    # Drop in reverse dependency order. Tables referencing operations
    # (permits, operation_allocations, credit_ledger, results, consents)
    # must go before operations.
    op.drop_table("restrictions")
    op.drop_table("free_requests")
    op.drop_table("free_buckets")
    op.drop_table("rate_buckets")
    op.drop_table("permit_scopes")
    op.drop_table("permits")
    op.drop_table("capacity_scopes")
    op.drop_table("signup_eligibility")
    op.drop_table("operation_allocations")
    op.drop_table("ledger_grants")
    op.drop_table("admin_adjustments")
    op.drop_table("credit_ledger")
    op.drop_table("results")
    op.drop_table("consents")
    op.drop_table("operations")
    op.drop_table("credit_grants")
    op.drop_table("credit_accounts")
