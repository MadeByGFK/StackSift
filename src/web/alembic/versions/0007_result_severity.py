"""Persist analysis outcome severity on results (issue #49).

Adds a nullable ``severity`` column to ``results``. Existing rows keep
NULL, which the My Reports page renders as the neutral dot.
"""
from alembic import op
import sqlalchemy as sa


revision = "0007_result_severity"
down_revision = "0006_merge_0004_0005"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("results", sa.Column("severity", sa.String(10), nullable=True))


def downgrade():
    op.drop_column("results", "severity")
