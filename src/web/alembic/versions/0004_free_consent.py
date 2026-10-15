"""Record free execution as terminal consumption of a paid consent."""
import sqlalchemy as sa
from alembic import op

revision = '0004_free_consent'
down_revision = '0003_phase2a_credits'
branch_labels = None
depends_on = None


def upgrade():
    if op.get_bind().dialect.name == 'sqlite':
        # SQLite supports a nullable REFERENCES column without rebuilding the
        # referenced consents table (which may already contain live operations).
        op.execute('ALTER TABLE consents ADD COLUMN consumed_by_free_request_id VARCHAR(255) '
                   'CONSTRAINT fk_consent_free_request REFERENCES free_requests(request_id)')
    else:
        op.add_column('consents', sa.Column('consumed_by_free_request_id', sa.String(255), nullable=True))
        op.create_foreign_key('fk_consent_free_request', 'consents', 'free_requests',
                              ['consumed_by_free_request_id'], ['request_id'])
    op.create_index('ix_consents_consumed_by_free_request_id', 'consents', ['consumed_by_free_request_id'], unique=True)


def downgrade():
    op.drop_index('ix_consents_consumed_by_free_request_id', table_name='consents')
    if op.get_bind().dialect.name != 'sqlite':
        op.drop_constraint('fk_consent_free_request', 'consents', type_='foreignkey')
    op.drop_column('consents', 'consumed_by_free_request_id')
