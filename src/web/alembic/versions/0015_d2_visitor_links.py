"""D2 attribution visitor links (issue #156).

One small table: the identity merge between a first-party
``d2_visitor_id`` cookie value and the user account it first
authenticated as. Funnel events themselves stay in the existing
``funnel_events`` table (#62) — this migration adds no events table.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0015_d2_visitor_links"
down_revision = "0014_sharing_rework"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "d2_visitor_links",
        sa.Column("visitor_id", sa.String(64), primary_key=True),
        sa.Column("user_id", UUID_TYPE,
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("merged_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_d2_visitor_links_user_id",
                    "d2_visitor_links", ["user_id"])


def downgrade():
    op.drop_index("ix_d2_visitor_links_user_id",
                  table_name="d2_visitor_links")
    op.drop_table("d2_visitor_links")
