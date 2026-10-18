"""SQLAlchemy models for StackSift Phase 1 (Accounts).

Phase 1 tables: users, oauth_accounts, sessions, email_verifications,
password_resets. Credit tables (credit_ledger, user_balances, credit_purchases)
are Phase 2/3 — NOT included here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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


class RateLimitBucket(Base):
    """Per-IP lock row for atomic shared rate limiting.

    One row per trusted client IP; it exists so concurrent admissions for
    the same IP can serialize on ``SELECT ... FOR UPDATE``. See
    app/rate_limit.py (PostgresRateLimiter).
    """

    __tablename__ = "rate_limit_buckets"

    trusted_ip = Column(String(45), primary_key=True)


class RateLimitHit(Base):
    """One row per admitted analysis.

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
