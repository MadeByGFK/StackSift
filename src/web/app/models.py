"""SQLAlchemy models for StackSift Phase 1 (Accounts).

Phase 1 tables: users, oauth_accounts, sessions, email_verifications,
password_resets. Credit tables (credit_ledger, user_balances, credit_purchases)
are Phase 2/3 — NOT included here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator

from app.db import Base


class GUID(TypeDecorator):
    """Platform-independent UUID: Postgres UUID, SQLite CHAR(36)."""

    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        value = value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        if dialect.name == "postgresql":
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    password_hash = Column(String(255), nullable=True)  # NULL for OAuth-only
    display_name = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    oauth_accounts = relationship("OAuthAccount", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_user"),)

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(20), nullable=False)  # 'google', 'github'
    provider_user_id = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user = relationship("User", back_populates="oauth_accounts")


class Session(Base):
    """User session. id is internal UUID PK; token_hash is SHA-256 of the cookie token."""

    __tablename__ = "sessions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    csrf_token = Column(String(64), nullable=False)

    user = relationship("User", back_populates="sessions")


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class OAuthState(Base):
    """Single-use authorization attempt; the browser carries only opaque secrets."""
    __tablename__ = "oauth_states"
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    state_hash = Column(String(64), unique=True, nullable=False, index=True)
    binding_hash = Column(String(64), nullable=False)
    provider = Column(String(20), nullable=False)
    action = Column(String(20), nullable=False)
    session_id = Column(GUID(), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True)
    nonce = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Phase 2A: Power-Up credits — accounting, operations, admission.
# Per StackSift Power-Ups Plan v11.1 (approved 2026-10-15).
#
# Stripe/payment tables (purchases, checkout_attempts, external_requests,
# refunds, provider_events, payment_disputes, etc.) are Phase 3 — NOT here.
# ---------------------------------------------------------------------------

from sqlalchemy import BigInteger, CheckConstraint, Index, Integer


class CreditAccount(Base):
    """One row per user. Stable serialization row for account-level locking.

    balance is debited at RESERVE time (not again at COMPLETE).
    Invariant A1: SUM(ledger.delta) == balance == SUM(grant.remaining - grant.reserved).
    """

    __tablename__ = "credit_accounts"

    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    balance = Column(Integer, nullable=False, default=0)
    ledger_sequence = Column(BigInteger, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (CheckConstraint("balance >= 0", name="ck_credit_accounts_balance_nonneg"),)


class CreditGrant(Base):
    """Individual credit grant. Spending allocates from specific grants (FIFO)."""

    __tablename__ = "credit_grants"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(20), nullable=False)  # 'purchase' | 'signup' | 'admin'
    source_key = Column(String(255), nullable=False)  # e.g. email for signup, purchase id
    issued = Column(Integer, nullable=False)
    remaining = Column(Integer, nullable=False)
    reserved = Column(Integer, nullable=False, default=0)
    purchase_id = Column(GUID(), nullable=True)  # Phase 3 FK; nullable until then
    revocation_queued_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("issued > 0", name="ck_grant_issued_positive"),
        CheckConstraint("remaining >= 0", name="ck_grant_remaining_nonneg"),
        CheckConstraint("reserved >= 0", name="ck_grant_reserved_nonneg"),
        CheckConstraint("reserved <= remaining", name="ck_grant_reserved_lte_remaining"),
        CheckConstraint("remaining <= issued", name="ck_grant_remaining_lte_issued"),
        UniqueConstraint("user_id", "source", "source_key", name="uq_grant_user_source_key"),
        # One signup grant per user, including revoked ones (abuse prevention).
        Index("ix_grant_signup_user", "user_id", unique=True,
              postgresql_where="source = 'signup'",
              sqlite_where=sa.text("source = 'signup'")),
    )


class CreditLedger(Base):
    """Append-only financial ledger. Rows never change or disappear (A6)."""

    __tablename__ = "credit_ledger"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    account_sequence = Column(BigInteger, nullable=False)
    event_key = Column(String(255), nullable=False)  # unique financial identity
    delta = Column(Integer, nullable=False)
    balance_after = Column(Integer, nullable=False)
    reason = Column(String(30), nullable=False)  # grant|reserve|operation_release|cash_refund|admin_revoke|admin_grant
    operation_id = Column(GUID(), ForeignKey("operations.id"), nullable=True)
    refund_id = Column(GUID(), nullable=True)  # Phase 3 FK
    adjustment_id = Column(GUID(), nullable=True)
    reverses_entry_id = Column(GUID(), ForeignKey("credit_ledger.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("delta != 0", name="ck_ledger_delta_nonzero"),
        CheckConstraint("balance_after >= 0", name="ck_ledger_balance_nonneg"),
        UniqueConstraint("user_id", "event_key", name="uq_ledger_user_event_key"),
        UniqueConstraint("user_id", "account_sequence", name="uq_ledger_user_sequence"),
        sa.ForeignKeyConstraint(["adjustment_id"], ["admin_adjustments.id"],
                                name="fk_ledger_adjustment_id"),
        Index("ix_ledger_reverses", "reverses_entry_id", unique=True,
              postgresql_where="reverses_entry_id IS NOT NULL",
              sqlite_where=sa.text("reverses_entry_id IS NOT NULL")),
    )


class LedgerGrant(Base):
    """Grant attribution for every ledger entry (mixed-grant reservations, reversals)."""

    __tablename__ = "ledger_grants"

    ledger_entry_id = Column(GUID(), ForeignKey("credit_ledger.id", ondelete="CASCADE"), primary_key=True)
    grant_id = Column(GUID(), ForeignKey("credit_grants.id", ondelete="CASCADE"), primary_key=True)
    signed_delta = Column(Integer, nullable=False)

    __table_args__ = (CheckConstraint("signed_delta != 0", name="ck_ledger_grant_delta_nonzero"),)


class Operation(Base):
    """Paid operation identity. Permanent rows; keys never reused (A11)."""

    __tablename__ = "operations"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(30), nullable=False)  # 'additional_analysis' | 'pdf' | 'batch'
    idempotency_key = Column(String(255), nullable=False)
    request_hash = Column(String(64), nullable=False)  # canonical input/options hash
    input_manifest = Column(Text, nullable=True)  # JSON describing inputs
    cost = Column(Integer, nullable=False)  # immutable snapshotted cost
    pricing_version = Column(Integer, nullable=False, default=1)
    consent_id = Column(GUID(), ForeignKey("consents.id", use_alter=True, name="fk_operations_consent_id"), nullable=True)
    status = Column(String(20), nullable=False, default="reserved")  # reserved|completed|failed|expired
    worker_id = Column(String(255), nullable=False)
    lease_generation = Column(Integer, nullable=False, default=1)
    lease_expires_at = Column(DateTime(timezone=True), nullable=False)
    result_id = Column(GUID(), ForeignKey("results.id", use_alter=True, name="fk_operations_result_id"), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String(50), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("cost > 0", name="ck_operation_cost_positive"),
        UniqueConstraint("user_id", "type", "idempotency_key", name="uq_operation_identity"),
    )


class OperationAllocation(Base):
    """Per-operation grant allocations. Remain after settlement for audit."""

    __tablename__ = "operation_allocations"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    operation_id = Column(GUID(), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False, index=True)
    grant_id = Column(GUID(), ForeignKey("credit_grants.id", ondelete="CASCADE"), nullable=False)
    quantity = Column(Integer, nullable=False)
    state = Column(String(20), nullable=False, default="reserved")  # reserved|consumed|released
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("quantity > 0", name="ck_allocation_quantity_positive"),
        UniqueConstraint("operation_id", "grant_id", name="uq_operation_grant"),
    )


class Result(Base):
    """Durable result bound to an operation. Exactly one owner, one origin (DB-enforced)."""

    __tablename__ = "results"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    anonymous_owner_hash = Column(String(64), nullable=True)
    operation_id = Column(GUID(), ForeignKey("operations.id"), nullable=True, unique=True)
    free_request_id = Column(String(255), nullable=True, unique=True)
    type = Column(String(30), nullable=False)  # 'analysis' | 'pdf' | 'batch'
    # Analysis outcome severity at store time: 'ok' | 'warnings' | 'errors'.
    # NULL = stored before severity existed (renders as the neutral dot).
    severity = Column(String(10), nullable=True)
    storage_manifest = Column(Text, nullable=False)  # JSON: where/how stored
    integrity_digest = Column(String(64), nullable=False)  # SHA-256 of artifact
    byte_count = Column(BigInteger, nullable=False)
    ready_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        # Exactly one owner: user_id XOR anonymous_owner_hash
        CheckConstraint(
            "(user_id IS NOT NULL) <> (anonymous_owner_hash IS NOT NULL)",
            name="ck_result_exactly_one_owner",
        ),
        # Exactly one origin: operation_id XOR free_request_id
        CheckConstraint(
            "(operation_id IS NOT NULL) <> (free_request_id IS NOT NULL)",
            name="ck_result_exactly_one_origin",
        ),
    )


class Consent(Base):
    """Server-bound authenticated approval for a paid operation."""

    __tablename__ = "consents"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    operation_type = Column(String(30), nullable=False)
    input_hash = Column(String(64), nullable=False)  # canonical input/options hash
    max_cost = Column(Integer, nullable=False)
    pricing_version = Column(Integer, nullable=False, default=1)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_by_operation_id = Column(GUID(), ForeignKey("operations.id"), nullable=True, unique=True)
    consumed_by_free_request_id = Column(String(255), ForeignKey("free_requests.request_id", use_alter=True, name="fk_consent_free_request"), nullable=True, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (CheckConstraint("max_cost > 0", name="ck_consent_max_cost_positive"),)


class AdminAdjustment(Base):
    """Audited manual grant/revoke. No arbitrary balance edits."""

    __tablename__ = "admin_adjustments"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(20), nullable=False)  # 'revoke' | 'grant'
    target_grant_id = Column(GUID(), ForeignKey("credit_grants.id"), nullable=True)
    quantity = Column(Integer, nullable=False)
    reason = Column(Text, nullable=False)
    evidence_ref = Column(String(255), nullable=True)
    actor = Column(String(255), nullable=False)
    approval_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(20), nullable=False, default="queued")  # queued|applied|cancelled
    applied_ledger_id = Column(GUID(), ForeignKey("credit_ledger.id", use_alter=True, name="fk_adjustments_applied_ledger"), nullable=True)
    request_key = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (CheckConstraint("quantity > 0", name="ck_adjustment_quantity_positive"),)


class SignupEligibility(Base):
    """Durable one-time signup grant eligibility. Survives account recreation."""

    __tablename__ = "signup_eligibility"

    email_normalized = Column(String(255), primary_key=True)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    issued_grant_id = Column(GUID(), ForeignKey("credit_grants.id"), nullable=True)
    grant_issued = Column(Boolean, nullable=False, default=False)
    granted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class CapacityScope(Base):
    """Stable counter rows for concurrency limits. Locked with FOR UPDATE."""

    __tablename__ = "capacity_scopes"

    scope_key = Column(String(255), primary_key=True)  # e.g. 'global:paid', 'user:<uuid>:paid'
    used = Column(Integer, nullable=False, default=0)
    max_limit = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("used >= 0", name="ck_capacity_used_nonneg"),
        CheckConstraint("max_limit > 0", name="ck_capacity_limit_positive"),
    )


class Permit(Base):
    """One permit per paid operation. Each releases at most once (A10)."""

    __tablename__ = "permits"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    operation_id = Column(GUID(), ForeignKey("operations.id", ondelete="CASCADE"), nullable=False, unique=True)
    worker_id = Column(String(255), nullable=False)
    lease_generation = Column(Integer, nullable=False, default=1)
    heartbeat_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    released_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class PermitScope(Base):
    """Permit membership in capacity scopes. Counters equal memberships (A10)."""

    __tablename__ = "permit_scopes"

    permit_id = Column(GUID(), ForeignKey("permits.id", ondelete="CASCADE"), primary_key=True)
    scope_key = Column(String(255), ForeignKey("capacity_scopes.scope_key"), primary_key=True)
    quantity = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class RateBucket(Base):
    """Atomic attempt counters for paid/abuse rate limits."""

    __tablename__ = "rate_buckets"

    policy = Column(String(50), nullable=False)
    owner = Column(String(255), nullable=False)  # user_id or 'global'
    window_start = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    max_limit = Column(Integer, nullable=False)
    config_version = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        sa.PrimaryKeyConstraint("policy", "owner", "window_start"),
        CheckConstraint("attempts >= 0", name="ck_rate_attempts_nonneg"),
    )


class FreeBucket(Base):
    """DB-backed free-tier quota buckets. Window from verified existing policy."""

    __tablename__ = "free_buckets"

    trusted_ip = Column(String(45), nullable=False)
    window_start = Column(DateTime(timezone=True), nullable=False)
    policy_version = Column(Integer, nullable=False, default=1)
    attempts = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        sa.PrimaryKeyConstraint("trusted_ip", "window_start", "policy_version"),
        CheckConstraint("attempts >= 0", name="ck_free_attempts_nonneg"),
    )


class FreeRequest(Base):
    """Permanent request identity for free analyses. Retired IDs never re-execute."""

    __tablename__ = "free_requests"

    request_id = Column(String(255), primary_key=True)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    anonymous_session_hash = Column(String(64), nullable=True)
    fingerprint = Column(String(64), nullable=False)  # input hash
    status = Column(String(20), nullable=False, default="in_progress")  # in_progress|completed|failed
    quota_bucket_trusted_ip = Column(String(45), nullable=True)
    quota_bucket_window_start = Column(DateTime(timezone=True), nullable=True)
    result_id = Column(GUID(), ForeignKey("results.id"), nullable=True)
    failure_code = Column(String(50), nullable=True)
    execution_generation = Column(Integer, nullable=False, default=1)
    deadline = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "(user_id IS NOT NULL) <> (anonymous_session_hash IS NOT NULL)",
            name="ck_free_request_exactly_one_owner",
        ),
    )


class Restriction(Base):
    """Spend/purchase restrictions. Multiple independent causes allowed."""

    __tablename__ = "restrictions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(20), nullable=False)  # 'spend' | 'purchase'
    cause_type = Column(String(50), nullable=False)  # 'dispute' | 'fraud' | 'manual' | 'invariant'
    cause_id = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)
    imposed_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    lifted_at = Column(DateTime(timezone=True), nullable=True)
    lift_evidence = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_restriction_active", "user_id", "action", "cause_type", "cause_id", unique=True,
              postgresql_where="lifted_at IS NULL",
              sqlite_where=sa.text("lifted_at IS NULL")),
    )


class RateLimitBucket(Base):
    """Per-IP lock row for atomic shared rate limiting (PR #28).

    One row per trusted client IP; it exists so concurrent admissions for
    the same IP can serialize on ``SELECT ... FOR UPDATE``. See
    app/rate_limit.py (PostgresRateLimiter).
    """

    __tablename__ = "rate_limit_buckets"

    trusted_ip = Column(String(45), primary_key=True)


class RateLimitHit(Base):
    """One row per admitted analysis (PR #28).

    A hit counts toward both the burst window and the hourly window based
    on ``hit_at``. Expired rows are deleted on write (per IP) plus an
    opportunistic hourly sweep.
    """

    __tablename__ = "rate_limit_hits"
    __table_args__ = (
        Index("ix_rate_limit_hits_ip_time", "trusted_ip", "hit_at"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    trusted_ip = Column(String(45), nullable=False)
    hit_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class NotifySignup(Base):
    """Notify-me capture for the credits launch (issue #67).

    SHORT bridge, not a destination: this table exists only until checkout
    ships (#68), at which point the capture form is removed and the collected
    addresses get exactly one launch email. Counts from this table are
    intent only — they are never demand evidence (GFK-013 §5.12). No
    third-party list tool: addresses are stored here, in our own database,
    with the source page recorded.
    """

    __tablename__ = "notify_signups"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    source = Column(String(50), nullable=False, default="credits")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class FunnelEvent(Base):
    """Activation and purchase funnel events (issue #62).

    Privacy contract: rows join by user_id (authenticated) or anon_id (a
    random pre-account session id) only. Log text, tokens, filenames, IPs,
    and contact PII are never recorded — app.funnel.record() enforces this
    on the meta payload. Counts are intent only, never demand evidence
    (GFK-013 §5.12).
    """

    __tablename__ = "funnel_events"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    anon_id = Column(String(64), nullable=True)
    event = Column(String(32), nullable=False)
    occurred_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    meta = Column(JSON, nullable=True)

    __table_args__ = (
        sa.Index("ix_funnel_events_user_event", "user_id", "event"),
        sa.Index("ix_funnel_events_anon_event", "anon_id", "event"),
        sa.Index("ix_funnel_events_occurred", "occurred_at"),
    )
