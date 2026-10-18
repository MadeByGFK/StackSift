"""Merge Alembic heads after PR #17 (0004) and PR #28 (0005) both land.

Applied by whoever merges SECOND. No schema changes.
"""
revision = "0006_merge_0004_0005"
down_revision = ("0004_free_consent", "0005_rate_limit_hits")
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
