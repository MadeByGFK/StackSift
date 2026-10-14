"""OAuth handlers for StackSift Phase 1 — Google + GitHub.

Security rules (v3 Section 4):
- NO auto-link by email. New OAuth identity = new account.
- Linking requires logged-in user + explicit confirmation.
- Validate state, issuer, audience, expiry, signature.
- GitHub: use only primary + verified email.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from fastapi import Request
from sqlalchemy.orm import Session as DBSession

from app.models import OAuthAccount, User

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
APP_URL = os.environ.get("APP_URL", "https://stacksift.goodfolkdigital.com")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


def generate_oauth_state() -> str:
    """Generate random state token for CSRF protection."""
    return secrets.token_urlsafe(32)


def get_google_auth_url(state: str) -> str:
    """Build Google OAuth authorization URL."""
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": f"{APP_URL}/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def get_github_auth_url(state: str) -> str:
    """Build GitHub OAuth authorization URL."""
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": f"{APP_URL}/auth/github/callback",
        "scope": "read:user user:email",
        "state": state,
    }
    return f"{GITHUB_AUTH_URL}?{urlencode(params)}"


async def exchange_google_code(code: str) -> dict:
    """Exchange authorization code for tokens. Returns token response."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{APP_URL}/auth/google/callback",
                "grant_type": "authorization_code",
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


async def get_google_userinfo(access_token: str) -> dict:
    """Fetch user profile from Google. Returns userinfo dict."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


async def exchange_github_code(code: str) -> str:
    """Exchange authorization code for access token. Returns token."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{APP_URL}/auth/github/callback",
            },
            headers={"Accept": "application/json"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


async def get_github_user(access_token: str) -> dict:
    """Fetch GitHub user profile."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            GITHUB_USER_URL,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()


async def get_github_primary_verified_email(access_token: str) -> str | None:
    """Fetch GitHub emails, return primary + verified email, or None.

    Security: Only trust primary AND verified emails. Never use unverified.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            GITHUB_EMAILS_URL,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=10.0,
        )
        resp.raise_for_status()
        emails = resp.json()
        for entry in emails:
            if entry.get("primary") and entry.get("verified"):
                return entry["email"]
        return None


def find_or_create_oauth_user(
    db: DBSession, provider: str, provider_user_id: str, email: str | None, display_name: str | None
) -> tuple[User, bool]:
    """Find existing OAuth account or create new user + OAuth link.

    NEVER auto-links to existing email-based account. If provider_user_id
    is new, always creates a new User.

    Returns (user, created_new).
    """
    oauth = (
        db.query(OAuthAccount)
        .filter(OAuthAccount.provider == provider, OAuthAccount.provider_user_id == provider_user_id)
        .first()
    )
    if oauth:
        return oauth.user, False

    # New OAuth identity = new account (no email matching)
    user = User(
        email=email or f"{provider}_{provider_user_id}@oauth.local",
        email_verified=bool(email),  # OAuth email is verified by provider
        password_hash=None,
        display_name=display_name,
    )
    db.add(user)
    db.flush()  # Get user.id

    oauth = OAuthAccount(
        user_id=user.id,
        provider=provider,
        provider_user_id=provider_user_id,
        email=email,
    )
    db.add(oauth)
    db.commit()
    db.refresh(user)
    return user, True


def link_oauth_to_user(
    db: DBSession,
    user: User,
    provider: str,
    provider_user_id: str,
    email: str | None,
) -> OAuthAccount:
    """Link OAuth identity to an already-logged-in user.

    Caller must verify user is authenticated and explicitly confirmed linking.
    Raises ValueError if this OAuth identity is already linked to another user.
    """
    existing = (
        db.query(OAuthAccount)
        .filter(OAuthAccount.provider == provider, OAuthAccount.provider_user_id == provider_user_id)
        .first()
    )
    if existing:
        if existing.user_id == user.id:
            return existing  # Already linked to this user
        raise ValueError("This OAuth account is already linked to another user.")

    oauth = OAuthAccount(
        user_id=user.id,
        provider=provider,
        provider_user_id=provider_user_id,
        email=email,
    )
    db.add(oauth)
    db.commit()
    db.refresh(oauth)
    return oauth
