"""Retention extension + shareable report links (issue #107).

Adds ``report_sharing`` (one row per report; SHA-256 token hash only,
generation fencing, revocation state — sharing is FREE, so there is no
entitlement/operation column) and ``report_actions`` (permanent
append-only owner-action identities for replay-safe retention purchases
and free share create/rotate/revoke actions).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0013_report_access"
down_revision = "0012_batch_free_claim"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "report_sharing",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("result_id", UUID_TYPE,
                  sa.ForeignKey("results.id", ondelete="CASCADE"), nullable=False),
        sa.Column("owner_user_id", UUID_TYPE,
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=True),
        sa.Column("generation", sa.Integer, nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("generation >= 0", name="ck_report_sharing_generation_nonneg"),
    )
    op.create_index("ix_report_sharing_result_id", "report_sharing",
                    ["result_id"], unique=True)
    op.create_index("ix_report_sharing_owner_user_id", "report_sharing",
                    ["owner_user_id"])
    op.create_index("ix_report_sharing_token_hash", "report_sharing",
                    ["token_hash"], unique=True)

    op.create_table(
        "report_actions",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("owner_user_id", UUID_TYPE,
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("result_id", UUID_TYPE,
                  sa.ForeignKey("results.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_kind", sa.String(30), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("generation", sa.Integer, nullable=True),
        sa.Column("resulting_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("operation_id", UUID_TYPE,
                  sa.ForeignKey("operations.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("owner_user_id", "result_id", "action_kind",
                            "idempotency_key", name="uq_report_action_identity"),
    )
    op.create_index("ix_report_actions_owner_user_id", "report_actions",
                    ["owner_user_id"])
    op.create_index("ix_report_actions_result_id", "report_actions",
                    ["result_id"])


def downgrade():
    op.drop_index("ix_report_actions_result_id", table_name="report_actions")
    op.drop_index("ix_report_actions_owner_user_id", table_name="report_actions")
    op.drop_table("report_actions")
    op.drop_index("ix_report_sharing_token_hash", table_name="report_sharing")
    op.drop_index("ix_report_sharing_owner_user_id", table_name="report_sharing")
    op.drop_index("ix_report_sharing_result_id", table_name="report_sharing")
    op.drop_table("report_sharing")
