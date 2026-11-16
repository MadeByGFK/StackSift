"""Per-report branding for Analysis Reports (issue #163).

Adds ``report_branding``: one row per Result (unique FK, ON DELETE
CASCADE for physical deletes). Expiry/soft-delete removal is explicit
application hygiene in ``credit_maintenance.cleanup_results``
(Amendment A2) — a soft delete never fires this cascade. Logo bytes
are the canonical Pillow re-encode validated at upload (A1).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0016_report_branding"
down_revision = "0015_d2_visitor_links"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "report_branding",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("result_id", UUID_TYPE,
                  sa.ForeignKey("results.id", ondelete="CASCADE"),
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
        sa.UniqueConstraint("result_id", name="uq_report_branding_result_id"),
    )
    op.create_index("ix_report_branding_result_id",
                    "report_branding", ["result_id"], unique=True)


def downgrade():
    op.drop_index("ix_report_branding_result_id",
                  table_name="report_branding")
    op.drop_table("report_branding")
