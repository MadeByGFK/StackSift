"""SQLAlchemy models for StackSift Phase 1 (Accounts).

Phase 1 tables: users, oauth_accounts, sessions, email_verifications,
password_resets. Credit tables (credit_ledger, user_balances, credit_purchases)
are Phase 2/3 — NOT included here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, JSON, String, Text, UniqueConstraint
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
    purchase_id = Column(GUID(), ForeignKey("credit_purchases.id"), nullable=True)
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
    # Issue #103 (trim B2): True when a batch operation claimed the shared
    # free hourly allowance for its first file. The claim lives on the
    # operation (no second FreeRequest is created) and is counted by
    # analysis_admission alongside FreeRequest rows, so alternating
    # single/batch routes cannot claim the tenth allowance twice.
    free_allowance_claim = Column(Boolean, nullable=False, default=False)
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
    # Issue #164 Phase A (Amendment A2): dollar-path origin. A Result is
    # born of exactly one of: a credit Operation, a free request, or a
    # product entitlement redemption.
    product_redemption_id = Column(GUID(), ForeignKey("entitlement_redemptions.id", use_alter=True, name="fk_results_product_redemption_id"), nullable=True, unique=True)
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
        # Exactly one origin of three (A2): operation XOR free_request
        # XOR product_redemption.
        CheckConstraint(
            "(CASE WHEN operation_id IS NOT NULL THEN 1 ELSE 0 END)"
            " + (CASE WHEN free_request_id IS NOT NULL THEN 1 ELSE 0 END)"
            " + (CASE WHEN product_redemption_id IS NOT NULL THEN 1 ELSE 0 END)"
            " = 1",
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


class D2VisitorLink(Base):
    """Identity merge for D2 attribution (issue #156).

    Links a first-party ``d2_visitor_id`` cookie value (the funnel
    ``anon_id``) to the user account it first signed up / logged in /
    completed OAuth with. Rows are never rewritten: first merge wins,
    so a later different user presenting the same visitor id cannot
    steal the link. The D2 report joins funnel events through this
    table; it stores no PII beyond the user FK itself.
    """

    __tablename__ = "d2_visitor_links"

    visitor_id = Column(String(64), primary_key=True)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    first_seen_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    merged_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
# ---------------------------------------------------------------------------
# Phase 3: Stripe purchases — settlement tables (issue #69).
#
# Money lives on CreditPurchase (amount_cents, currency, Stripe payment
# intent); credits live on CreditGrant (linked via purchase_id) and the
# append-only CreditLedger (event_key f"grant:{grant.id}"). Reconciliation
# (#72) joins: Stripe payment <-> credit_purchases <-> credit_grants
# (purchase_id) <-> credit_ledger (event_key).
# ---------------------------------------------------------------------------


class CreditPurchase(Base):
    """One credit-pack purchase attempt.

    Created as 'pending' by POST /credits/checkout BEFORE the Stripe session
    is created, so a crash between Stripe and our DB cannot produce a paid
    session with no local record. The webhook (issue #69) transitions
    pending -> completed exactly once; rows stuck in 'pending' are abandoned
    checkouts for reconciliation (#72) to expire.
    """

    __tablename__ = "credit_purchases"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    # Stripe Checkout Session id; NULL until the session is created (or when
    # session creation failed after the pending row was written).
    stripe_session_id = Column(String(255), unique=True, nullable=True)
    stripe_payment_intent_id = Column(String(255), nullable=True)
    pack_id = Column(String(20), nullable=False)
    credits = Column(Integer, nullable=False)  # snapshot of the pack at checkout
    # Money side, authoritative from Stripe at completion; NULL while pending.
    amount_cents = Column(Integer, nullable=True)
    currency = Column(String(10), nullable=True)
    pricing_version = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    # 'pending' | 'completed' | 'failed'
    stripe_event_id = Column(String(255), nullable=True)  # completing event
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("credits > 0", name="ck_purchase_credits_positive"),
        CheckConstraint(
            "status IN ('pending','completed','failed')",
            name="ck_purchase_status_valid",
        ),
        CheckConstraint(
            "(status != 'completed') OR (amount_cents IS NOT NULL AND amount_cents > 0)",
            name="ck_purchase_completed_has_amount",
        ),
    )


class StripeWebhookEvent(Base):
    """Append-only log of Stripe webhook deliveries.

    The primary key IS the idempotency guard: a redelivered event collides
    on stripe_event_id and is answered 200 'duplicate' without touching
    money. outcome is one of 'processed' | 'duplicate' | 'ignored' | 'failed'.
    """

    __tablename__ = "stripe_webhook_events"

    stripe_event_id = Column(String(255), primary_key=True)
    event_type = Column(String(60), nullable=False)
    purchase_id = Column(GUID(), ForeignKey("credit_purchases.id"), nullable=True)
    # Issue #164 Phase A (A3): product-family join. At most one of the
    # two purchase FKs is ever set; zero stays valid for
    # unknown/unsupported events.
    product_purchase_id = Column(GUID(), ForeignKey("product_purchases.id", use_alter=True, name="fk_webhook_product_purchase_id"), nullable=True)
    attempts = Column(Integer, nullable=False, default=1)
    outcome = Column(String(20), nullable=False)
    note = Column(String(255), nullable=True)
    received_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "outcome IN ('processed','duplicate','ignored','failed')",
            name="ck_webhook_event_outcome_valid",
        ),
        CheckConstraint(
            "(purchase_id IS NULL) OR (product_purchase_id IS NULL)",
            name="ck_webhook_event_at_most_one_purchase",
        ),
    )


# ---------------------------------------------------------------------------
# Phase 3: daily Stripe-to-ledger reconciliation (issue #72).
# ---------------------------------------------------------------------------


class PaymentReconciliation(Base):
    """One reconciliation record per UTC calendar day (issue #72).

    Compares Stripe completed payments against ledger credit grants per day
    and per pack, to the cent. status is one of
    'clean' | 'mismatch' | 'error' | 'skipped'.

    - clean: Stripe and ledger agree on every pack; recorded as evidence.
    - mismatch: at least one pack differs or a record on one side has no
      counterpart on the other; ``differences`` names the specific records
      and a founder-visible alert is raised (``alert_pending`` until the
      alert email is delivered).
    - error: the job itself failed (Stripe unreachable, DB error); the day
      is retried on the next cycle, never silently dropped.
    - skipped: Stripe checkout is not configured, so no payments could
      exist; honest recording rather than a fabricated clean day.

    Refunds and disputes count as negative entries on the Stripe side even
    when the ledger holds no matching reversal yet — they are economics,
    and an unmatched one is exactly the anomaly the founder must see
    (GFK-013 §6).
    """

    __tablename__ = "payment_reconciliations"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    recon_date = Column(Date, nullable=False, unique=True)  # UTC calendar day
    status = Column(String(20), nullable=False)
    stripe_gross_cents = Column(Integer, nullable=False, default=0)
    stripe_refund_cents = Column(Integer, nullable=False, default=0)
    stripe_dispute_cents = Column(Integer, nullable=False, default=0)
    ledger_gross_cents = Column(Integer, nullable=False, default=0)
    ledger_refund_cents = Column(Integer, nullable=False, default=0)
    # pack_id -> {stripe_gross_cents, stripe_refund_cents,
    #             stripe_dispute_cents, ledger_gross_cents,
    #             ledger_refund_cents, stripe_net_cents,
    #             ledger_net_cents, diff_cents}
    per_pack = Column(JSON, nullable=True)
    # Issue #164 Phase A (A8): family partition (pack | product |
    # unknown) computed once at ingestion; schema_version 2 records
    # carry per_family. Version 1 rows (pack-only era) reprocess
    # compatibly: readers treat a missing per_family as pack-only.
    schema_version = Column(Integer, nullable=False, default=1)
    per_family = Column(JSON, nullable=True)
    # List of {kind, detail...} for every record that does not pair up.
    differences = Column(JSON, nullable=True)
    alert_sent = Column(Boolean, nullable=False, default=False)
    alert_pending = Column(Boolean, nullable=False, default=False)
    error_note = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('clean','mismatch','error','skipped')",
            name="ck_recon_status_valid",
        ),
    )


# ---------------------------------------------------------------------------
# Issue #107: retention extension + shareable report links.
#
# ReportSharing was, under #107, the ONE sharing row per report. Issue
# #135 reworks it to ONE row per (report, format): each row carries the
# SHA-256 hash of its current 256-bit bearer token (the lookup key), a
# generation counter fencing stale create/rotate replays, revocation
# state, the link's format (pdf/txt/json/csv) and — #135 ONLY — the raw
# token, because Settings -> Report Access must list a copyable live
# link per link ("copy = reshare"), which hash-only storage cannot
# redisplay. The raw token is exposed ONLY to the owning user on the
# authenticated Settings page; public lookup still goes through the
# hash. Sharing creation is FREE (founder ruling 2026-11-01, trim T1):
# there is deliberately NO entitlement/operation column — no charge,
# consent, or admission exists for create/rotate/revoke, ever. The
# #129 export unlock GATES creation of pdf/json/csv links; it is not a
# charge collected by sharing.
#
# ReportAction is the permanent, append-only identity record for owner
# actions on a report (retention purchases and free share actions). It
# makes same-key replays identifiable forever — including after the
# action-receipt Result's payload has been cleaned up — without storing
# any bearer secret.
# ---------------------------------------------------------------------------


class ReportSharing(Base):
    __tablename__ = "report_sharing"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    result_id = Column(GUID(), ForeignKey("results.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    owner_user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    token_hash = Column(String(64), nullable=True, unique=True, index=True)
    # Issue #135: the format this link serves (pdf|txt|json|csv). NULL
    # on pre-#135 rows, which are treated as txt (the old free text
    # share) if they are ever read.
    share_format = Column(String(10), nullable=True)
    # Issue #135: raw bearer token, stored ONLY so the owner's
    # Settings -> Report Access page can list/copy the live link.
    # Cleared together with token_hash on revoke/cleanup.
    raw_token = Column(String(64), nullable=True)
    generation = Column(Integer, nullable=False, default=0)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("generation >= 0", name="ck_report_sharing_generation_nonneg"),
        UniqueConstraint("result_id", "share_format",
                         name="uq_report_sharing_result_format"),
    )


class ReportBranding(Base):
    """Issue #163: per-report branding for a paid Analysis Report.

    1:1 with ``results.id`` (FK ON DELETE CASCADE covers physical
    deletes only; expiry/soft-delete removal is explicit in
    ``credit_maintenance.cleanup_results`` — Amendment A2). Owner is
    enforced through the Result. A row with every field NULL is the
    CLEARED state (Amendment A8(e)): clear retains the row, and the
    row's existence is what defeats stale stored-PDF replay (A3).
    ``logo_bytes`` holds ONLY the canonical re-encoded bytes produced
    by ``app.branding.validate_and_canonicalize_logo`` (A1).
    """

    __tablename__ = "report_branding"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    result_id = Column(GUID(), ForeignKey("results.id", ondelete="CASCADE"),
                       nullable=False)
    business_name = Column(Text, nullable=True)
    client_name = Column(Text, nullable=True)
    report_title = Column(Text, nullable=True)
    accent = Column(String(7), nullable=True)
    logo_bytes = Column(sa.LargeBinary, nullable=True)
    logo_media_type = Column(String(20), nullable=True)
    logo_sha256 = Column(String(64), nullable=True)
    logo_width = Column(Integer, nullable=True)
    logo_height = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("result_id", name="uq_report_branding_result_id"),
        Index("ix_report_branding_result_id", "result_id", unique=True),
    )


class ReportAction(Base):
    __tablename__ = "report_actions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    owner_user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    result_id = Column(GUID(), ForeignKey("results.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    action_kind = Column(String(30), nullable=False)  # retention_extension | share_create | share_rotate | share_revoke
    idempotency_key = Column(String(255), nullable=False)
    request_hash = Column(String(64), nullable=False)
    generation = Column(Integer, nullable=True)  # sharing generation after the action
    resulting_expiry = Column(DateTime(timezone=True), nullable=True)  # retention outcome
    operation_id = Column(GUID(), ForeignKey("operations.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("owner_user_id", "result_id", "action_kind",
                         "idempotency_key", name="uq_report_action_identity"),
    )


# ---------------------------------------------------------------------------
# Issue #164 Phase A: per-product dollar purchases + entitlements.
#
# Generic engine proven on the Investigation Report ($9). Legacy credit
# tables are untouched by this phase. Settlement grants an Entitlement
# and nothing else — no credits, no ledger rows, no consents, ever.
# Redemption is a durable EntitlementRedemption record (A1), mirroring
# the credit Operation reserve/complete/release discipline: worker
# identity, lease generation, executor-stop fencing on recovery.
# ---------------------------------------------------------------------------


class ProductPurchase(Base):
    """One per-product purchase attempt (mirror of CreditPurchase).

    Created 'pending' BEFORE the Stripe session exists. The webhook
    transitions pending -> completed exactly once and creates the
    single Entitlement. Refund/dispute reversals (A5/F3) record
    provenance on reversal_* without rewriting payment history.
    """

    __tablename__ = "product_purchases"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    sku = Column(String(40), nullable=False)
    source_result_id = Column(GUID(), ForeignKey("results.id"), nullable=False, index=True)
    stripe_session_id = Column(String(255), unique=True, nullable=True)
    stripe_payment_intent_id = Column(String(255), nullable=True)
    # Checkout-time snapshots (A4): settlement asserts the event equals
    # ALL of these — amount, currency, and the Stripe Price ID.
    amount_cents = Column(Integer, nullable=True)
    currency = Column(String(10), nullable=True)
    stripe_price_id = Column(String(255), nullable=True)
    pricing_version = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    # 'pending' | 'completed' | 'failed' | 'refunded' | 'disputed'
    stripe_event_id = Column(String(255), nullable=True)
    reversal_event_id = Column(String(255), nullable=True)
    reversal_kind = Column(String(20), nullable=True)
    # 'refund' | 'dispute_open' | 'dispute_lost' | 'dispute_won'
    reversed_at = Column(DateTime(timezone=True), nullable=True)
    # Remediation2 P2-C (migration 0018): cumulative refunded cents
    # from the latest charge.refunded event (Stripe's amount_refunded
    # is cumulative per charge). Partials persist their amount here
    # so reconciliation's product ledger refund total can include
    # them; NULL on rows never refunded (and on pre-0018 full-refund
    # rows, where reconciliation falls back to amount_cents).
    refunded_cents = Column(Integer, nullable=True)
    # Remediation3 (migration 0019): dedicated reversal accounting
    # fields that dispute/refund processing cannot erase or move.
    # ``refunded_at`` is the processing time of the refund event that
    # set the current (maximum) cumulative ``refunded_cents``;
    # ``dispute_lost_at`` records that a dispute was lost, ever,
    # regardless of later reversal_kind overwrites. Reconciliation
    # keys product refund/dispute deductions off these fields (plus
    # ``refunded_cents``) bucketed by ``completed_at`` — the charge
    # creation / settlement day — never off reversal_*/reversed_at,
    # which track only the LATEST reversal event's provenance.
    refunded_at = Column(DateTime(timezone=True), nullable=True)
    dispute_lost_at = Column(DateTime(timezone=True), nullable=True)
    # Remediation4 (migration 0020): the AMOUNT of the dispute Stripe
    # reported (a dispute can be for less than the full charge), so
    # reconciliation's ledger-side lost-dispute deduction can mirror
    # the Stripe side's per-charge cap instead of always deducting
    # the full unrefunded remainder. NULL on rows whose dispute
    # events predate the field (full-remainder fallback there).
    disputed_cents = Column(Integer, nullable=True)
    # Remediation4 (migration 0020): the Stripe charge creation
    # timestamp, persisted at settlement from the completed session
    # object's ``created`` value (the charge/session creation anchor
    # the Stripe reconciliation fetch keys on). Reconciliation
    # buckets product gross AND reversal membership by this anchor,
    # so a charge created before midnight whose settlement webhook
    # is processed after midnight lands on ONE day on both sides.
    # NULL on pre-0020 rows, which fall back to completed_at.
    stripe_charge_created_at = Column(DateTime(timezone=True), nullable=True)
    needs_manual_review = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','completed','failed','refunded','disputed')",
            name="ck_product_purchase_status_valid",
        ),
        CheckConstraint(
            "(status != 'completed') OR (amount_cents IS NOT NULL AND amount_cents > 0)",
            name="ck_product_purchase_completed_has_amount",
        ),
        # P2-1 (A7/F1): at most ONE pending purchase per
        # (buyer, source, sku) — the DB-level backstop for the
        # SELECT-then-act reuse in create_pending_product_purchase.
        Index("ix_product_purchases_pending_unique",
              "user_id", "source_result_id", "sku", unique=True,
              postgresql_where="status = 'pending'",
              sqlite_where=sa.text("status = 'pending'")),
    )


class Entitlement(Base):
    """The buyer's right to redeem one product for one source report.

    Status set (A1): available | reserved | redeemed | revoked |
    refund_eligible (F5 terminal state after the redemption window
    lapses). 'reserved' is a projection of a live EntitlementRedemption
    row — it is only ever written in the same transaction that inserts
    that row. `version` is the CAS counter every transition fences on.
    """

    __tablename__ = "entitlements"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    product_purchase_id = Column(GUID(), ForeignKey("product_purchases.id"),
                                 nullable=False, unique=True)
    sku = Column(String(40), nullable=False)
    source_result_id = Column(GUID(), ForeignKey("results.id"), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="available")
    version = Column(Integer, nullable=False, default=0)
    # F5: source Result expiry + 30 days, fixed at settlement.
    redemption_deadline = Column(DateTime(timezone=True), nullable=True)
    redeemed_result_id = Column(GUID(), ForeignKey("results.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    redeemed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('available','reserved','redeemed','revoked','refund_eligible')",
            name="ck_entitlement_status_valid",
        ),
        # P2-1 (F1): at most ONE live (available|reserved) entitlement
        # per (buyer, source, sku) — the DB-level guarantee behind the
        # duplicate-purchase block, closing the SELECT-then-act race.
        Index("ix_entitlements_live_unique",
              "user_id", "source_result_id", "sku", unique=True,
              postgresql_where="status IN ('available', 'reserved')",
              sqlite_where=sa.text("status IN ('available', 'reserved')")),
    )


class EntitlementRedemption(Base):
    """Durable redemption record (A1) — the dollar path's Operation.

    status: reserved | completed | released | stopped. A 'stopped' row
    is a crashed reservation whose executor-stop evidence has not yet
    arrived: the entitlement stays out of circulation (still projected
    'reserved') until the retry-after-stopped path releases it.
    """

    __tablename__ = "entitlement_redemptions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    entitlement_id = Column(GUID(), ForeignKey("entitlements.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    source_result_id = Column(GUID(), ForeignKey("results.id"), nullable=False)
    request_hash = Column(String(64), nullable=False)
    worker_id = Column(String(255), nullable=False)
    lease_generation = Column(Integer, nullable=False, default=1)
    lease_expires_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(20), nullable=False, default="reserved")
    failure_code = Column(String(50), nullable=True)
    result_id = Column(GUID(), ForeignKey("results.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('reserved','completed','released','stopped')",
            name="ck_redemption_status_valid",
        ),
        # P3-9 disposition (recorded, not silent): A1's text says
        # entitlement_id "unique while non-terminal", but the partial
        # index covers status='reserved' only. That is functionally
        # equivalent here: a 'stopped' row is released (retry path)
        # before any re-reserve can be attempted, and the entitlement
        # stays projected 'reserved' while stopped, so no second live
        # reservation can be inserted through any code path.
        Index("ix_redemption_entitlement_live", "entitlement_id", unique=True,
              postgresql_where="status = 'reserved'",
              sqlite_where=sa.text("status = 'reserved'")),
    )
