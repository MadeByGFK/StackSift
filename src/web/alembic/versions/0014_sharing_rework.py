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

Downgrade data-loss policy (PR #138 remediation, finding 5):
downgrading restores the pre-#135 unique index on ``result_id``
(one row per report), which cannot hold while per-format rows
exist — so downgrade is inherently LOSSY for per-format links.
Before restoring uniqueness it consolidates to ONE row per
``result_id``: the earliest-created ACTIVE row is kept (active =
non-revoked, i.e. ``revoked_at IS NULL``, with a token —
``token_hash IS NOT NULL`` — preferred first), with a deterministic
tie-break of ``created_at`` then ``id``. Every other row for that
report is DELETED, and its link stops serving once the downgrade
completes. This is explicit and deliberate: a rollback keeps at
most the single earliest live link per report.
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


def _consolidate_to_one_row_per_result():
    """Delete all but the kept row per result_id (see module docstring)."""
    bind = op.get_bind()
    rows = bind.execute(sa.text(
        "SELECT id, result_id, revoked_at, token_hash, created_at "
        "FROM report_sharing")).fetchall()
    by_result = {}
    for row in rows:
        by_result.setdefault(row[1], []).append(row)

    def _keep_key(row):
        # Prefer a non-revoked row with a token, then earliest
        # created_at, then id — deterministic on both dialects
        # (created_at/id are compared as strings, which orders
        # ISO timestamps and UUID/CHAR ids consistently).
        active = 0 if (row[2] is None and row[3] is not None) else 1
        return (active, "" if row[4] is None else str(row[4]), str(row[0]))

    for _result_id, group in by_result.items():
        if len(group) <= 1:
            continue
        group.sort(key=_keep_key)
        for doomed in group[1:]:
            bind.execute(
                sa.text("DELETE FROM report_sharing WHERE id = :row_id"),
                {"row_id": doomed[0]})


def downgrade():
    _consolidate_to_one_row_per_result()
    with op.batch_alter_table("report_sharing") as batch_op:
        batch_op.drop_constraint("uq_report_sharing_result_format",
                                 type_="unique")
        batch_op.drop_index("ix_report_sharing_result_id")
        batch_op.create_index("ix_report_sharing_result_id",
                              ["result_id"], unique=True)
    op.drop_column("report_sharing", "raw_token")
    op.drop_column("report_sharing", "share_format")
