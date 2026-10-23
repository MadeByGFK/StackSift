"""Merge Alembic heads after PR #84 (0009_phase3_purchases) and PR #86
(0009_funnel_events) both land on staging/p1.

Applied by the PR that merges SECOND (PR #86). No schema changes —
both branches are additive on top of 0008_notify_signups.
"""
revision = "0010_merge_heads"
down_revision = ("0009_funnel_events", "0009_phase3_purchases")
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
