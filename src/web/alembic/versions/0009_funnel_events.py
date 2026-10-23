"""Activation and purchase funnel events (issue #62).

funnel_events: one row per funnel milestone, joined by user_id (authenticated)
or anon_id (random pre-account session id) only. No log text, tokens,
filenames, IPs, or contact PII are ever stored — enforced in app/funnel.py.

NOTE: if issue #69 (0009_phase3_purchases) merges first, this revision and
that one are both heads on 0008_notify_signups; resolve with a one-file
alembic merge revision in a follow-up.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")

revision = "0009_funnel_events"
down_revision = "0008_notify_signups"
branch_labels = None
depends_on = None


def upgrade():
    # FK declared inline (per 0003 convention): SQLite accepts FKs in
    # CREATE TABLE but not via ALTER ADD CONSTRAINT.
    op.create_table(
        "funnel_events",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("user_id", UUID_TYPE, sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("anon_id", sa.String(64), nullable=True),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("meta", sa.JSON(), nullable=True),
    )
    op.create_index("ix_funnel_events_user_event", "funnel_events", ["user_id", "event"])
    op.create_index("ix_funnel_events_anon_event", "funnel_events", ["anon_id", "event"])
    op.create_index("ix_funnel_events_occurred", "funnel_events", ["occurred_at"])


def downgrade():
    op.drop_index("ix_funnel_events_occurred", table_name="funnel_events")
    op.drop_index("ix_funnel_events_anon_event", table_name="funnel_events")
    op.drop_index("ix_funnel_events_user_event", table_name="funnel_events")
    op.drop_table("funnel_events")
