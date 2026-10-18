"""Shared rate-limit state: per-IP lock buckets + admitted-hit log.

NOTE on revision ordering: down_revision is 0002_oauth_state (the
staging/p1 head). PR #17 adds 0003_phase2a_credits -> 0004_free_consent from
the same parent; whichever PR merges second must add an Alembic merge
migration. The limiter degrades gracefully when free_requests is absent.
"""
from alembic import op
import sqlalchemy as sa


revision = "0005_rate_limit_hits"
down_revision = "0002_oauth_state"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "rate_limit_buckets",
        sa.Column("trusted_ip", sa.String(45), primary_key=True),
    )
    op.create_table(
        "rate_limit_hits",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("trusted_ip", sa.String(45), nullable=False),
        sa.Column("hit_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_rate_limit_hits_ip_time", "rate_limit_hits", ["trusted_ip", "hit_at"]
    )


def downgrade():
    op.drop_index("ix_rate_limit_hits_ip_time", table_name="rate_limit_hits")
    op.drop_table("rate_limit_hits")
    op.drop_table("rate_limit_buckets")
