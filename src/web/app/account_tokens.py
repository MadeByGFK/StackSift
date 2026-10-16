"""Atomic account-token redemption, with one transaction for all security effects."""
from datetime import datetime, timezone
from sqlalchemy import select, update
from app.auth import hash_token
from app.models import EmailVerification, PasswordReset, Session, User


def redeem(db, model, token, password_hash=None):
    # Serialize ALL token redemptions for this user (including different tokens).
    # UPDATE obtains a write lock on SQLite and a row lock on PostgreSQL before
    # reading mutable token state. No-op assignment leaves updated_at unchanged.
    owner = select(model.user_id).where(model.token_hash == hash_token(token)).scalar_subquery()
    user_id = db.execute(update(User).where(User.id == owner).values(
        updated_at=User.updated_at).returning(User.id)).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if user_id is None:
        db.rollback()
        return False
    claimed = db.execute(update(model).where(
        model.token_hash == hash_token(token), model.used_at.is_(None), model.expires_at > now,
    ).values(used_at=now).returning(model.id)).scalar_one_or_none()
    if claimed is None:
        db.rollback()
        return False
    db.execute(update(model).where(model.user_id == user_id, model.used_at.is_(None)).values(used_at=now))
    if model is EmailVerification:
        db.execute(update(User).where(User.id == user_id).values(email_verified=True))
    elif model is PasswordReset and password_hash:
        db.execute(update(User).where(User.id == user_id).values(password_hash=password_hash))
        db.execute(update(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None)).values(revoked_at=now))
    else:
        db.rollback()
        raise ValueError("Unsupported account token operation")
    db.commit()
    return True
