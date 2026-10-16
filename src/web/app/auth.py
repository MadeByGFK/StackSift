"""Authentication helpers for StackSift Phase 1.

Password hashing (bcrypt), session tokens, CSRF tokens, rate limiting,
Have I Been Pwned breach checking.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import httpx
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session as DBSession

from app.models import Session as SessionModel

# --- Password validation ---

PASSWORD_MIN_LENGTH = 12


def validate_password_strength(password: str) -> str | None:
    """Return error message if password is too weak, else None."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if len(password.encode("utf-8")) > 72:
        return "Password must be at most 72 bytes in UTF-8."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return "Password must contain at least one special character."
    return None


def hash_password(password: str) -> str:
    """Hash password with bcrypt cost 12."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def check_password_breached(password: str, timeout: float = 5.0) -> bool:
    """Check Have I Been Pwned via k-anonymity (first 5 chars of SHA-1).

    Returns True if password found in breaches. Returns False on API error
    (fail open — don't block signup if HIBP is down).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=timeout,
            headers={"User-Agent": "StackSift"},
        )
        resp.raise_for_status()
        for line in resp.text.splitlines():
            if line.split(":")[0].upper() == suffix:
                return True
        return False
    except (httpx.HTTPError, ValueError, IndexError):
        return False


# --- Tokens ---

def generate_token() -> str:
    """Generate a random 32-byte token (hex, 64 chars)."""
    return secrets.token_hex(32)


def hash_token(token: str) -> str:
    """SHA-256 hash of a token (stored in DB, never store raw token)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalize_email(email: str) -> str:
    """Lowercase and trim email."""
    return email.strip().lower()


# --- Sessions ---

SESSION_COOKIE = "__Host-stacksift_session"
CSRF_COOKIE = "__Host-stacksift_csrf"
# A valid cost-12 hash keeps missing/OAuth-only login attempts on the bcrypt path.
DUMMY_PASSWORD_HASH = bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt(rounds=12)).decode()
SESSION_TTL = timedelta(days=30)


def create_session(
    db: DBSession,
    user_id,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[SessionModel, str]:
    """Create a new session. Returns (session, raw_token)."""
    raw_token = generate_token()
    csrf_token = generate_token()
    session = SessionModel(
        token_hash=hash_token(raw_token),
        user_id=user_id,
        expires_at=datetime.now(timezone.utc) + SESSION_TTL,
        ip_address=ip_address,
        user_agent=user_agent,
        csrf_token=csrf_token,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session, raw_token


def get_session_from_cookie(db: DBSession, request: Request) -> SessionModel | None:
    """Validate session cookie. Returns session or None."""
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return None
    token_hash = hash_token(raw_token)
    return db.query(SessionModel).filter(
        SessionModel.token_hash == token_hash,
        SessionModel.revoked_at.is_(None),
        SessionModel.expires_at > datetime.now(timezone.utc),
    ).populate_existing().first()


def revoke_session(db: DBSession, session: SessionModel) -> None:
    """Revoke a single session."""
    session.revoked_at = datetime.now(timezone.utc)
    db.commit()


def revoke_all_sessions(db: DBSession, user_id, except_session_id=None) -> None:
    """Revoke all sessions for a user, optionally keeping one."""
    q = db.query(SessionModel).filter(
        SessionModel.user_id == user_id,
        SessionModel.revoked_at.is_(None),
    )
    if except_session_id is not None:
        q = q.filter(SessionModel.id != except_session_id)
    q.update({SessionModel.revoked_at: datetime.now(timezone.utc)})
    db.commit()


# --- CSRF ---

def validate_csrf(request: Request, session: SessionModel) -> None:
    """Validate CSRF token from X-CSRF-Token header. Raises 403 if invalid."""
    token = request.headers.get("X-CSRF-Token")
    if not token or not hmac.compare_digest(token, session.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


# --- Rate limiting (in-memory, per-process) ---

class AuthRateLimiter:
    """Simple in-memory rate limiter for auth endpoints.

    Maps key -> list of timestamps. Not distributed — per-process only.
    For Phase 1 this is acceptable (single-worker Uvicorn).
    """

    def __init__(self):
        self._attempts: dict[str, list[datetime]] = {}

    def check(self, key: str, max_attempts: int, window_seconds: int) -> bool:
        """Return True if allowed, False if rate-limited."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        attempts = self._attempts.get(key, [])
        attempts = [t for t in attempts if t > cutoff]
        self._attempts[key] = attempts
        if len(attempts) >= max_attempts:
            return False
        attempts.append(now)
        return True

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)


# Global rate limiter instance
auth_limiter = AuthRateLimiter()

# Rate limit configs: (max_attempts, window_seconds)
RATE_LIMITS = {
    "oauth": (10, 60),     # OAuth starts/min per IP
    "login": (5, 60),       # 5/min per IP
    "signup": (3, 3600),    # 3/hour per IP
    "forgot": (3, 3600),    # 3/hour per IP
    "verify_resend": (3, 3600),  # 3/hour per email
    "reset": (5, 3600),     # 5/hour per IP
}


def check_rate_limit(kind: str, key: str) -> None:
    """Check rate limit, raise 429 if exceeded."""
    max_attempts, window = RATE_LIMITS[kind]
    if not auth_limiter.check(f"{kind}:{key}", max_attempts, window):
        raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
