"""Notify-me capture for the credits launch (issue #67).

Short bridge only: stores addresses for the single launch email sent when
checkout ships (#68). Counts from this table are intent, never demand
evidence (GFK-013 §5.12).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0008_notify_signups"
down_revision = "0007_result_severity"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "notify_signups",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_notify_signups_email", "notify_signups", ["email"], unique=True)


def downgrade():
    op.drop_index("ix_notify_signups_email", table_name="notify_signups")
    op.drop_table("notify_signups")
