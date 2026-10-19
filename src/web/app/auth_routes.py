"""Accounts-only routes. All POSTs require CSRF; OAuth state is server-owned."""
from __future__ import annotations

import hmac
import httpx
import jwt
import uuid
from datetime import datetime, timedelta, timezone

from pathlib import Path

from fastapi import BackgroundTasks, APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from fastapi.routing import APIRoute

from app import auth as auth_helpers
from app import email as email_helpers
from app import oauth as oauth_helpers
from app.client_ip import client_ip as _client_ip
from app.db import get_db
from app.models import EmailVerification, PasswordReset, User, OAuthState
from app.account_tokens import redeem

class AccountRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def secured(request):
            response = await handler(request)
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            return response
        return secured


async def require_csrf(request: Request, db: DBSession = Depends(get_db)):
    if request.method != "POST":
        return
    session = auth_helpers.get_session_from_cookie(db, request)
    expected = session.csrf_token if session else request.cookies.get(auth_helpers.CSRF_COOKIE)
    token = request.headers.get("X-CSRF-Token") or (await request.form()).get("csrf_token")
    if not expected or not isinstance(token, str) or not hmac.compare_digest(token, expected):
        raise HTTPException(403, "Invalid CSRF token. Reload the page and try again.")


router = APIRouter(route_class=AccountRoute, dependencies=[Depends(require_csrf)])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")

# Generic responses (no enumeration)
GENERIC_SIGNUP = "If this email is valid, a verification link has been sent."
GENERIC_FORGOT = "If an account exists for this email, a reset link has been sent."


def _set_session_cookie(response: JSONResponse | RedirectResponse, token: str) -> None:
    response.set_cookie(
        key=auth_helpers.SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=30 * 24 * 3600,
        path="/",
    )


def _clear_session_cookie(response: JSONResponse | RedirectResponse) -> None:
    response.delete_cookie(key=auth_helpers.SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")


def _get_current_user(request: Request, db: DBSession) -> User | None:
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return None
    return session.user


# --- HTML pages ---

def _page(request, db, name, **context):
    session = auth_helpers.get_session_from_cookie(db, request)
    user = session.user if session else None
    csrf = session.csrf_token if session else request.cookies.get(auth_helpers.CSRF_COOKIE) or auth_helpers.generate_token()
    response = templates.TemplateResponse(request, name, {"error": None, "message": None, "csrf_token": csrf, "current_user": user, **context})
    if not session:
        response.set_cookie(auth_helpers.CSRF_COOKIE, csrf, secure=True, httponly=True, samesite="lax", path="/")
    return response


@router.get("/auth/csrf")
async def csrf_token(request: Request, db: DBSession = Depends(get_db)):
    session = auth_helpers.get_session_from_cookie(db, request)
    csrf = session.csrf_token if session else request.cookies.get(auth_helpers.CSRF_COOKIE) or auth_helpers.generate_token()
    response = JSONResponse({"csrf_token": csrf})
    if not session:
        response.set_cookie(auth_helpers.CSRF_COOKIE, csrf, secure=True, httponly=True, samesite="lax", path="/")
    return response


@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request, db: DBSession = Depends(get_db)):
    return _page(request, db, "signup.html")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: DBSession = Depends(get_db)):
    return _page(request, db, "login.html")


@router.get("/forgot", response_class=HTMLResponse)
async def forgot_page(request: Request, db: DBSession = Depends(get_db)):
    return _page(request, db, "forgot.html")


@router.get("/reset", response_class=HTMLResponse)
async def reset_page(request: Request, token: str = "", db: DBSession = Depends(get_db)):
    return _page(request, db, "reset.html", token=token)


@router.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request, token: str = "", db: DBSession = Depends(get_db)):
    # GET is deliberately non-consuming: email scanners must not redeem links.
    return _page(request, db, "verify.html", token=token)


@router.post("/auth/verify")
async def verify_email(request: Request, token: str = Form(...), db: DBSession = Depends(get_db)):
    if not redeem(db, EmailVerification, token):
        return JSONResponse({"error": "Invalid or expired verification link."}, status_code=400)
    # Phase 2A: grant the approved 3-credit signup reward (idempotent per email).
    # Failures here must not break verification; log and continue.
    try:
        from app import credits as credits_helpers
        from app.models import User as UserModel
        # Find the user by the verification token we just redeemed
        from app.auth import hash_token as _hash_token
        verif = db.query(EmailVerification).filter(
            EmailVerification.token_hash == _hash_token(token)).first()
        if verif:
            user = db.get(UserModel, verif.user_id)
            if user:
                credits_helpers.grant_signup_reward(db, user.id, user.email)
                db.commit()
    except Exception:
        db.rollback()
        import logging
        logging.getLogger(__name__).exception("signup reward grant failed")
    return JSONResponse({"message": "Email verified. You can now log in."})


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: DBSession = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    session = auth_helpers.get_session_from_cookie(db, request)
    sessions = (
        db.query(auth_helpers.SessionModel)
        .filter(
            auth_helpers.SessionModel.user_id == user.id,
            auth_helpers.SessionModel.revoked_at.is_(None),
            auth_helpers.SessionModel.expires_at > datetime.now(timezone.utc),
        )
        .order_by(auth_helpers.SessionModel.created_at.desc())
        .all()
    )
    # Query linked OAuth providers for connected-accounts display
    from app.models import OAuthAccount
    oauth_links = (
        db.query(OAuthAccount.provider)
        .filter(OAuthAccount.user_id == user.id)
        .all()
    )
    linked_providers = {row[0] for row in oauth_links}
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "current_user": user,
            "sessions": sessions,
            "current_session_id": str(session.id) if session else None,
            "csrf_token": session.csrf_token if session else "",
            "linked_providers": linked_providers,
        },
    )


# --- API endpoints ---

@router.post("/auth/signup")
async def signup(
    request: Request,
    background: BackgroundTasks,
    email: str = Form(...),
    password: str = Form(...),
    db: DBSession = Depends(get_db),
):
    ip = _client_ip(request)
    auth_helpers.check_rate_limit("signup", ip)

    email_norm = auth_helpers.normalize_email(email)
    if len(email_norm) > 255 or email_norm.count("@") != 1 or any(c.isspace() for c in email_norm) or not all(email_norm.split("@")):
        return JSONResponse({"error": "Enter a valid email address."}, status_code=400)

    # Validate password (before checking email exists — no enumeration via timing)
    pw_error = auth_helpers.validate_password_strength(password)
    if pw_error:
        return JSONResponse({"error": pw_error}, status_code=400)

    # Check breach (fail open)
    if auth_helpers.check_password_breached(password):
        return JSONResponse(
            {"error": "This password has appeared in a data breach. Please choose a different password."},
            status_code=400,
        )

    # Hash for both existing and new addresses to remove the large timing split.
    password_hash = auth_helpers.hash_password(password)
    existing = db.query(User).filter(User.email == email_norm).first()
    if not existing:
        try:
            existing = User(email=email_norm, email_verified=False, password_hash=password_hash)
            db.add(existing)
            db.flush()
        except IntegrityError:
            # Race: another request created the user. Re-query for consistent handling.
            db.rollback()
            existing = db.query(User).filter(User.email == email_norm).first()
            if existing and existing.email_verified:
                return JSONResponse(
                    {"error": "This email is already registered. Try logging in instead."},
                    status_code=409,
                )
            return JSONResponse({"message": GENERIC_SIGNUP})
    if existing.email_verified:
        # Account already exists and is verified — tell the user directly
        # instead of the misleading "verification link sent" message.
        # (Founder decision 2026-10-18: UX clarity over enumeration protection on signup.)
        db.commit()
        return JSONResponse(
            {"error": "This email is already registered. Try logging in instead."},
            status_code=409,
        )
    token = auth_helpers.generate_token()
    db.add(EmailVerification(user_id=existing.id, token_hash=auth_helpers.hash_token(token),
                             expires_at=datetime.now(timezone.utc) + timedelta(hours=24)))
    background.add_task(email_helpers.send_verification_email, existing.email, token)
    db.commit()
    return JSONResponse({"message": GENERIC_SIGNUP})


@router.post("/auth/resend-verification")
async def resend_verification(
    request: Request,
    background: BackgroundTasks,
    email: str = Form(...),
    db: DBSession = Depends(get_db),
):
    """Re-send verification email for an existing unverified account.

    Security (GFD 2026-10-18): this endpoint NEVER creates accounts and NEVER
    accepts a password. The previous client-side dummy-password approach
    (ResendOnly123!) could create accounts with a predictable password.
    """
    email_norm = auth_helpers.normalize_email(email)
    if len(email_norm) > 255 or email_norm.count("@") != 1:
        return JSONResponse({"message": GENERIC_SIGNUP})

    # Rate limits: per-email (prevents targeted harassment) + per-IP
    # (prevents distributed abuse). GFD 2026-10-18: fix verify_resend key.
    auth_helpers.check_rate_limit("verify_resend", email_norm)
    auth_helpers.check_rate_limit("resend_ip", _client_ip(request))

    existing = db.query(User).filter(User.email == email_norm).first()
    # Only re-send for existing UNVERIFIED accounts. Never create, never
    # reveal whether the account exists (generic response).
    if existing and not existing.email_verified:
        token = auth_helpers.generate_token()
        db.add(EmailVerification(user_id=existing.id, token_hash=auth_helpers.hash_token(token),
                                 expires_at=datetime.now(timezone.utc) + timedelta(hours=24)))
        background.add_task(email_helpers.send_verification_email, existing.email, token)
        db.commit()
    return JSONResponse({"message": GENERIC_SIGNUP})


@router.post("/auth/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: DBSession = Depends(get_db),
):
    ip = _client_ip(request)
    auth_helpers.check_rate_limit("login", ip)

    email_norm = auth_helpers.normalize_email(email)
    user = db.query(User).filter(User.email == email_norm).with_for_update().first()

    # Generic error — don't reveal whether email exists or password wrong
    valid_password = auth_helpers.verify_password(password, user.password_hash if user and user.password_hash else auth_helpers.DUMMY_PASSWORD_HASH)
    if not user or not user.password_hash or not valid_password:
        return JSONResponse({"error": "Invalid email or password."}, status_code=401)

    if not user.email_verified:
        return JSONResponse(
            {"error": "Please verify your email before logging in. Check your inbox for a verification link."},
            status_code=403,
        )

    old_session = auth_helpers.get_session_from_cookie(db, request)
    if old_session:
        old_session.revoked_at = datetime.now(timezone.utc)
    user.last_login_at = datetime.now(timezone.utc)

    session, raw_token = auth_helpers.create_session(
        db, user.id, ip_address=ip, user_agent=request.headers.get("User-Agent")
    )
    response = JSONResponse({"message": "Logged in.", "csrf_token": session.csrf_token})
    _set_session_cookie(response, raw_token)
    return response


@router.post("/auth/logout")
async def logout(request: Request, db: DBSession = Depends(get_db)):
    session = auth_helpers.get_session_from_cookie(db, request)
    if session:
        # CSRF check for cookie-authenticated state change
        auth_helpers.revoke_session(db, session)
    # If this is an AJAX request (from auth_form_script.js), return JSON
    # and let the JS handle navigation via data-success-url.
    # Otherwise (plain HTML form), redirect to home.
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        response = JSONResponse({"message": "Logged out."})
    else:
        response = RedirectResponse("/", status_code=303)
    _clear_session_cookie(response)
    return response


@router.post("/auth/forgot")
async def forgot(
    request: Request,
    background: BackgroundTasks,
    email: str = Form(...),
    db: DBSession = Depends(get_db),
):
    ip = _client_ip(request)
    auth_helpers.check_rate_limit("forgot", ip)

    email_norm = auth_helpers.normalize_email(email)
    user = db.query(User).filter(User.email == email_norm).with_for_update().first()
    if user and user.password_hash:
        # Only send reset if user has a password (not OAuth-only)
        token = auth_helpers.generate_token()
        reset = PasswordReset(
            user_id=user.id,
            token_hash=auth_helpers.hash_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add(reset)
        db.commit()
        background.add_task(email_helpers.send_password_reset_email, user.email, token)
    # Always generic success — no enumeration
    return JSONResponse({"message": GENERIC_FORGOT}, status_code=200)


@router.post("/auth/reset")
async def reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    db: DBSession = Depends(get_db),
):
    ip = _client_ip(request)
    auth_helpers.check_rate_limit("reset", ip)

    pw_error = auth_helpers.validate_password_strength(new_password)
    if pw_error:
        return JSONResponse({"error": pw_error}, status_code=400)

    if auth_helpers.check_password_breached(new_password):
        return JSONResponse(
            {"error": "This password has appeared in a data breach. Please choose a different password."},
            status_code=400,
        )

    password_hash = auth_helpers.hash_password(new_password)
    if not redeem(db, PasswordReset, token, password_hash):
        return JSONResponse({"error": "Invalid or expired reset link."}, status_code=400)
    response = JSONResponse({"message": "Password reset. Please log in with your new password."})
    _clear_session_cookie(response)
    return response


@router.get("/auth/me")
async def me(request: Request, db: DBSession = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "id": str(user.id),
        "email": user.email,
        "email_verified": user.email_verified,
        "display_name": user.display_name,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


# --- Sessions management ---

@router.get("/auth/balance")
async def balance(request: Request, db: DBSession = Depends(get_db)):
    """Return credit balance for the logged-in user (for nav display)."""
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return JSONResponse({"balance": None})
    try:
        from app import credits as credits_helpers
        summary = credits_helpers.get_balance_summary(db, session.user_id)
        return JSONResponse({"balance": summary["balance"]})
    except Exception:
        return JSONResponse({"balance": None})

@router.get("/auth/sessions")
async def list_sessions(request: Request, db: DBSession = Depends(get_db)):
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    sessions = (
        db.query(auth_helpers.SessionModel)
        .filter(
            auth_helpers.SessionModel.user_id == session.user_id,
            auth_helpers.SessionModel.revoked_at.is_(None),
            auth_helpers.SessionModel.expires_at > datetime.now(timezone.utc),
        )
        .order_by(auth_helpers.SessionModel.created_at.desc())
        .all()
    )
    return {
        "sessions": [
            {
                "id": str(s.id),
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "is_current": str(s.id) == str(session.id),
            }
            for s in sessions
        ],
        "current_session_id": str(session.id),
    }


@router.post("/auth/sessions/{session_id}/revoke")
async def revoke_session(request: Request, session_id: uuid.UUID, db: DBSession = Depends(get_db)):
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    target = (
        db.query(auth_helpers.SessionModel)
        .filter(
            auth_helpers.SessionModel.id == session_id,
            auth_helpers.SessionModel.user_id == session.user_id,
        )
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Session not found")
    if str(target.id) == str(session.id):
        raise HTTPException(status_code=400, detail="Cannot revoke your current session. Use logout instead.")
    auth_helpers.revoke_session(db, target)
    return {"message": "Session revoked."}


@router.post("/auth/sessions/revoke-all")
async def revoke_all_sessions(request: Request, db: DBSession = Depends(get_db)):
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    auth_helpers.revoke_all_sessions(db, session.user_id, except_session_id=session.id)
    return {"message": "All other sessions revoked."}


# --- OAuth: browser secret + DB state; cookies never choose the action ---
OAUTH_COOKIE = "__Host-stacksift_oauth"


def _start_oauth(request, provider, action, db):
    if provider not in ("google", "github"):
        raise HTTPException(400, "Unsupported provider.")
    configured = (oauth_helpers.GOOGLE_CLIENT_ID and oauth_helpers.GOOGLE_CLIENT_SECRET) if provider == "google" else (oauth_helpers.GITHUB_CLIENT_ID and oauth_helpers.GITHUB_CLIENT_SECRET)
    if not configured:
        raise HTTPException(503, "This sign-in provider is not configured.")
    session = auth_helpers.get_session_from_cookie(db, request)
    if action == "link" and not session:
        raise HTTPException(401, "Sign in before linking an account.")
    if action == "login" and session:
        # An authenticated browser must explicitly use the protected link flow.
        return RedirectResponse("/settings", status_code=303)
    auth_helpers.check_rate_limit("oauth", _client_ip(request))
    db.execute(delete(OAuthState).where(OAuthState.expires_at <= datetime.now(timezone.utc)))
    state, binding, nonce = (auth_helpers.generate_token() for _ in range(3))
    db.add(OAuthState(state_hash=auth_helpers.hash_token(state), binding_hash=auth_helpers.hash_token(binding),
                      provider=provider, action=action, session_id=session.id if session else None,
                      nonce=nonce, expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)))
    db.commit()
    url = oauth_helpers.get_google_auth_url(state, nonce) if provider == "google" else oauth_helpers.get_github_auth_url(state)
    response = RedirectResponse(url, status_code=303)
    if session is None:
        _clear_session_cookie(response)
    response.set_cookie(OAUTH_COOKIE, binding, httponly=True, secure=True, samesite="lax", max_age=600, path="/")
    return response


@router.get("/auth/google")
async def google_login(request: Request, db: DBSession = Depends(get_db)):
    return _start_oauth(request, "google", "login", db)


@router.get("/auth/github")
async def github_login(request: Request, db: DBSession = Depends(get_db)):
    return _start_oauth(request, "github", "login", db)


@router.post("/auth/link/{provider}")
async def oauth_link_start(request: Request, provider: str, db: DBSession = Depends(get_db)):
    return _start_oauth(request, provider, "link", db)


def _bound_session(db, request, attempt):
    current = auth_helpers.get_session_from_cookie(db, request)
    if attempt.session_id is None:
        if current is not None or request.cookies.get(auth_helpers.SESSION_COOKIE):
            raise HTTPException(400, "Session changed. Start sign-in again.")
    elif current is None or current.id != attempt.session_id:
        raise HTTPException(400, "Session changed. Start account linking again.")
    return current


async def _callback(request, provider, code, state, db):
    binding = request.cookies.get(OAUTH_COOKIE, "")
    if not state or not binding:
        raise HTTPException(400, "Invalid or expired OAuth state.")
    # Atomic claim: simultaneous requests cannot both contact the provider.
    attempt = db.execute(update(OAuthState).where(
        OAuthState.state_hash == auth_helpers.hash_token(state),
        OAuthState.binding_hash == auth_helpers.hash_token(binding),
        OAuthState.provider == provider, OAuthState.used_at.is_(None),
        OAuthState.expires_at > datetime.now(timezone.utc),
    ).values(used_at=datetime.now(timezone.utc)).returning(OAuthState)).scalar_one_or_none()
    if attempt is None:
        db.rollback()
        raise HTTPException(400, "Invalid or expired OAuth state.")
    db.commit()  # Consume even on denial, failed exchange, or changed session.
    current = _bound_session(db, request, attempt)
    if not code:
        raise HTTPException(400, "Authorization was not completed. Please try again.")
    try:
        if provider == "google":
            tokens = await oauth_helpers.exchange_google_code(code)
            info = await oauth_helpers.get_google_identity(tokens, attempt.nonce)
            identity, email, name = info["sub"], info["email"], info.get("name")
        else:
            access = await oauth_helpers.exchange_github_code(code)
            info = await oauth_helpers.get_github_user(access)
            if not isinstance(info, dict):
                raise ValueError("Invalid GitHub profile")
            identity = info.get("id")
            if type(identity) is not int or identity <= 0:
                raise ValueError("Invalid GitHub identity")
            identity = str(identity)
            email = await oauth_helpers.get_github_primary_verified_email(access)
            name = info.get("name") or info.get("login")
        oauth_helpers.validate_identity(provider, identity, email)
    except (ValueError, KeyError, TypeError, httpx.HTTPError, jwt.PyJWTError):
        raise HTTPException(400, "Unable to verify provider identity and email. Please try again.") from None
    # Refresh after network I/O, so logout/revocation while authorizing is honored.
    db.expire_all()
    if attempt.session_id is not None:
        owner = db.query(auth_helpers.SessionModel.user_id).filter_by(id=attempt.session_id).scalar()
        db.execute(update(User).where(User.id == owner).values(updated_at=User.updated_at))
        db.query(auth_helpers.SessionModel).filter_by(id=attempt.session_id).with_for_update().populate_existing().first()
    current = _bound_session(db, request, attempt)
    try:
        if attempt.action == "link":
            if current is None:
                raise HTTPException(401, "Sign in before linking an account.")
            oauth_helpers.link_oauth_to_user(db, current.user, provider, identity, email)
            response = RedirectResponse("/settings", status_code=303)
        elif attempt.action == "login" and current is None:
            user, created = oauth_helpers.find_or_create_oauth_user(db, provider, identity, email, name)
            if created:
                # BR-02: grant the approved 3-credit signup reward for verified
                # OAuth signups (idempotent per email; never on link/re-login).
                # Failures must not break login; log and continue.
                try:
                    from app import credits as credits_helpers
                    credits_helpers.grant_signup_reward(db, user.id, user.email)
                    db.commit()
                except Exception:
                    db.rollback()
                    import logging
                    logging.getLogger(__name__).exception("signup reward grant failed")
            user.last_login_at = datetime.now(timezone.utc)
            session, raw = auth_helpers.create_session(db, user.id, ip_address=_client_ip(request), user_agent=request.headers.get("User-Agent"))
            response = RedirectResponse("/", status_code=303)
            _set_session_cookie(response, raw)
        else:
            raise HTTPException(400, "Invalid authorization action.")
    except oauth_helpers.OAuthConflict as exc:
        response = _page(request, db, "oauth_error.html", error=str(exc))
        response.status_code = 409
    response.delete_cookie(OAUTH_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response


@router.get("/auth/google/callback")
async def google_callback(request: Request, code: str = "", state: str = "", db: DBSession = Depends(get_db)):
    return await _callback(request, "google", code, state, db)


@router.get("/auth/github/callback")
async def github_callback(request: Request, code: str = "", state: str = "", db: DBSession = Depends(get_db)):
    return await _callback(request, "github", code, state, db)
