"""Account-level branding (Pricing/Report cleanup, 2026-11-16).

Adds ``account_branding``: one row per User (unique FK, ON DELETE
CASCADE for physical deletes). Branding moved from the per-report
``report_branding`` surface (#163) to the account level — it is
managed once on Settings and applies to every paid report PDF the
account generates afterwards. Logo bytes are the canonical Pillow
re-encode validated at upload (A1), exactly as in 0016. No data is
migrated from ``report_branding`` (founder direction 2026-11-16);
the legacy table is untouched by this migration.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0024_account_branding"
down_revision = "0023_phase_b_digest_bindings"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "account_branding",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE,
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("business_name", sa.Text, nullable=True),
        sa.Column("client_name", sa.Text, nullable=True),
        sa.Column("report_title", sa.Text, nullable=True),
        sa.Column("accent", sa.String(7), nullable=True),
        sa.Column("logo_bytes", sa.LargeBinary, nullable=True),
        sa.Column("logo_media_type", sa.String(20), nullable=True),
        sa.Column("logo_sha256", sa.String(64), nullable=True),
        sa.Column("logo_width", sa.Integer, nullable=True),
        sa.Column("logo_height", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", name="uq_account_branding_user_id"),
    )
    op.create_index("ix_account_branding_user_id",
                    "account_branding", ["user_id"], unique=True)


def downgrade():
    op.drop_index("ix_account_branding_user_id",
                  table_name="account_branding")
    op.drop_table("account_branding")
