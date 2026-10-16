"""Database setup for StackSift Phase 1 (Accounts).

Uses SQLAlchemy ORM with Alembic migrations. DATABASE_URL env var points to
Postgres in production (Railway), SQLite in-memory for tests.
"""

from __future__ import annotations

import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./stacksift.db")

# Normalize Postgres URL scheme: SQLAlchemy 2.x defaults to psycopg (v3)
# driver for postgresql:// URLs, but we ship psycopg2-binary. Force psycopg2.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# SQLite needs check_same_thread=False for FastAPI
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a DB session, closes it after request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables (used in tests and dev; production uses Alembic)."""
    # Import models so Base knows about them
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
