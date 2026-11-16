"""SS-format report ID on results (issue #170 fidelity, S1-C2).

Adds the nullable unique ``results.ss_id`` column. Values are
assigned at store time by the application (daily sequence); existing
rows stay NULL and their display ID derives deterministically.
"""
import sqlalchemy as sa
from alembic import op

revision = "0022_report_ss_id"
down_revision = "0021_product_purchase_disputes"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("results", sa.Column("ss_id", sa.String(20), nullable=True))
    op.create_index("ix_results_ss_id", "results", ["ss_id"], unique=True)


def downgrade():
    op.drop_index("ix_results_ss_id", table_name="results")
    op.drop_column("results", "ss_id")
