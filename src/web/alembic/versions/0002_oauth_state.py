"""Persist single-use, session-bound OAuth authorization attempts."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0002_oauth_state"
down_revision = "0001_phase1_accounts"
branch_labels = None
depends_on = None
UUID_TYPE = sa.String(36).with_variant(UUID(as_uuid=True), "postgresql")


def upgrade():
    op.create_table(
        "oauth_states",
        sa.Column("id", UUID_TYPE, primary_key=True),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("binding_hash", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("session_id", UUID_TYPE, sa.ForeignKey("sessions.id", ondelete="CASCADE")),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_oauth_states_state_hash", "oauth_states", ["state_hash"], unique=True)


def downgrade():
    op.drop_table("oauth_states")
