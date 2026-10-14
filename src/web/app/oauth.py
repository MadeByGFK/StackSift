"""OAuth handlers for StackSift Phase 1 — Google + GitHub.

Security rules (v3 Section 4):
- NO auto-link by email. Collisions require explicit authenticated linking.
- Linking requires logged-in user + explicit confirmation.
- Validate state, issuer, audience, expiry, signature.
- GitHub: use only primary + verified email.
"""

from __future__ import annotations

import os
import hmac
import jwt
from urllib.parse import urlencode

import httpx
from sqlalchemy.exc import IntegrityError

from app.models import OAuthAccount, User
from app.auth import normalize_email

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
APP_URL = os.environ.get("APP_URL", "https://stacksift.goodfolkdigital.com")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


def get_google_auth_url(state: str, nonce: str) -> str:
    """Build Google OAuth authorization URL."""
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": f"{APP_URL}/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "nonce": nonce,
        "prompt": "select_account",
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


async def get_google_identity(tokens: dict, nonce: str) -> dict:
    """Verify Google's signed ID token against fixed issuer keys, never token URLs."""
    if not isinstance(tokens, dict):
        raise ValueError("Invalid Google token response")
    encoded = tokens.get("id_token")
    if not isinstance(encoded, str):
        raise ValueError("Missing Google identity")
    header = jwt.get_unverified_header(encoded)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ValueError("Invalid signing algorithm")
    async with httpx.AsyncClient() as client:
        resp = await client.get("https://www.googleapis.com/oauth2/v3/certs", timeout=10.0)
        resp.raise_for_status()
    key_set = resp.json()
    if not isinstance(key_set, dict) or not isinstance(key_set.get("keys"), list):
        raise ValueError("Invalid Google signing keys")
    keys = [key for key in key_set["keys"] if isinstance(key, dict) and key.get("kid") == header["kid"]]
    if len(keys) != 1:
        raise ValueError("Unknown signing key")
    key = jwt.PyJWK.from_dict(keys[0], algorithm="RS256").key
    claims = jwt.decode(encoded, key, algorithms=["RS256"], audience=GOOGLE_CLIENT_ID,
                        issuer=["https://accounts.google.com", "accounts.google.com"],
                        options={"require": ["iss", "aud", "exp", "iat", "sub", "nonce"]})
    if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and "azp" not in claims:
        raise ValueError("Missing authorized party")
    if claims.get("azp", GOOGLE_CLIENT_ID) != GOOGLE_CLIENT_ID:
        raise ValueError("Invalid authorized party")
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise ValueError("Invalid nonce")
    if claims.get("email_verified") is not True:
        raise ValueError("Google email must be verified")
    validate_identity("google", claims.get("sub"), claims.get("email"))
    return claims


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
        if not isinstance(emails, list) or not all(isinstance(entry, dict) for entry in emails):
            raise ValueError("Invalid GitHub email response")
        for entry in emails:
            if entry.get("primary") is True and entry.get("verified") is True:
                return entry["email"]
        return None


class OAuthConflict(ValueError):
    pass


def validate_identity(provider, provider_user_id, email):
    if provider not in ("google", "github") or not isinstance(provider_user_id, str) or not provider_user_id.strip() or len(provider_user_id) > 255:
        raise ValueError("Invalid provider identity")
    if not isinstance(email, str) or len(email) > 255 or "@" not in email or any(c.isspace() for c in email.strip()):
        raise ValueError("A verified provider email is required")


def find_or_create_oauth_user(db, provider, provider_user_id, email, display_name):
    """Never link by email. A collision requires login and an explicit settings link."""
    validate_identity(provider, provider_user_id, email)
    email = normalize_email(email)
    existing = db.query(OAuthAccount).filter_by(provider=provider, provider_user_id=provider_user_id).first()
    if existing:
        return existing.user, False
    message = "Sign in to your existing StackSift account, then link this provider in Account settings."
    if db.query(User).filter_by(email=email).first():
        raise OAuthConflict(message)
    name = display_name[:255] if isinstance(display_name, str) else None
    user = User(email=email, email_verified=True, password_hash=None, display_name=name)
    try:
        db.add(user)
        db.flush()
        db.add(OAuthAccount(user_id=user.id, provider=provider, provider_user_id=provider_user_id, email=email))
        db.commit()
    except IntegrityError:
        db.rollback()
        # Concurrent signup/link never silently changes identity ownership.
        raise OAuthConflict(message) from None
    return user, True


def link_oauth_to_user(db, user, provider, provider_user_id, email):
    """Caller must hold the initiating authenticated session and validate CSRF/state."""
    validate_identity(provider, provider_user_id, email)
    existing = db.query(OAuthAccount).filter_by(provider=provider, provider_user_id=provider_user_id).first()
    if existing:
        if existing.user_id != user.id:
            raise OAuthConflict("This provider account is already linked to another account.")
        return existing
    account = OAuthAccount(user_id=user.id, provider=provider, provider_user_id=provider_user_id, email=normalize_email(email))
    try:
        db.add(account)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise OAuthConflict("This provider account is already linked to another account.") from None
    return account
