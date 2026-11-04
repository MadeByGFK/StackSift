"""Sharing rework (issue #135): per-format share links.

``report_sharing`` goes from one row per report to one row per
(report, format): the unique index on ``result_id`` becomes a plain
index, a unique constraint on (result_id, share_format) takes its
place, and two columns are added — ``share_format`` (pdf/txt/json/csv;
NULL on pre-#135 rows, read as txt) and ``raw_token`` (stored only so
the owner's Settings -> Report Access page can list/copy the live
link; the public lookup still uses ``token_hash``).

Batch mode is used for the index/constraint changes because SQLite
cannot ALTER constraints in place (the migration test-suite runs the
full chain on SQLite; PostgreSQL accepts the same operations).
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_sharing_rework"
down_revision = "0013_report_access"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("report_sharing",
                  sa.Column("share_format", sa.String(10), nullable=True))
    op.add_column("report_sharing",
                  sa.Column("raw_token", sa.String(64), nullable=True))
    with op.batch_alter_table("report_sharing") as batch_op:
        batch_op.drop_index("ix_report_sharing_result_id")
        batch_op.create_index("ix_report_sharing_result_id",
                              ["result_id"], unique=False)
        batch_op.create_unique_constraint(
            "uq_report_sharing_result_format",
            ["result_id", "share_format"])


def downgrade():
    with op.batch_alter_table("report_sharing") as batch_op:
        batch_op.drop_constraint("uq_report_sharing_result_format",
                                 type_="unique")
        batch_op.drop_index("ix_report_sharing_result_id")
        batch_op.create_index("ix_report_sharing_result_id",
                              ["result_id"], unique=True)
    op.drop_column("report_sharing", "raw_token")
    op.drop_column("report_sharing", "share_format")
