"""Batch free-allowance claim on operations (issue #103, trim B2).

Adds ``operations.free_allowance_claim``: a batch operation whose first
file used the shared free hourly allowance records the claim on its own
row, so durable free-request accounting can count it alongside
FreeRequest rows in the same transaction that reserves its credits.
"""
import sqlalchemy as sa
from alembic import op


revision = "0012_batch_free_claim"
down_revision = "0011_payment_reconciliations"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "operations",
        sa.Column("free_allowance_claim", sa.Boolean, nullable=False,
                  server_default="0"),
    )


def downgrade():
    op.drop_column("operations", "free_allowance_claim")
