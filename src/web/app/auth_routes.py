"""Auth routes for StackSift Phase 1.

Endpoints:
- POST /auth/signup — Create account (email/password)
- POST /auth/login — Login
- POST /auth/logout — Logout
- GET  /auth/verify — Verify email (token in query)
- POST /auth/forgot — Request password reset
- POST /auth/reset — Reset password
- GET  /auth/google, /auth/google/callback — Google OAuth
- GET  /auth/github, /auth/github/callback — GitHub OAuth
- GET  /auth/me — Current user info
- GET  /auth/sessions — List active sessions
- POST /auth/sessions/{id}/revoke — Revoke a session
- POST /auth/sessions/revoke-all — Revoke all sessions
- GET  /signup, /login, /forgot, /reset, /verify, /settings — HTML pages

Security:
- Signup/forgot always return generic success (no email enumeration)
- CSRF required on all POST with cookie auth
- Rate limits per v3 Section 6
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession

from app import auth as auth_helpers
from app import email as email_helpers
from app import oauth as oauth_helpers
from app.client_ip import client_ip as _client_ip
from app.db import get_db
from app.models import EmailVerification, PasswordReset, User

router = APIRouter()
templates = Jinja2Templates(directory="src/web/app/templates")

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
    response.delete_cookie(key=auth_helpers.SESSION_COOKIE, path="/")


def _get_current_user(request: Request, db: DBSession) -> User | None:
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return None
    return session.user


# --- HTML pages ---

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse(request, "signup.html", {"error": None})


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.get("/forgot", response_class=HTMLResponse)
async def forgot_page(request: Request):
    return templates.TemplateResponse(request, "forgot.html", {"error": None, "message": None})


@router.get("/reset", response_class=HTMLResponse)
async def reset_page(request: Request, token: str = ""):
    return templates.TemplateResponse(request, "reset.html", {"error": None, "token": token})


@router.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request, token: str = "", db: DBSession = Depends(get_db)):
    """Verify email from link."""
    if not token:
        return templates.TemplateResponse(request, "verify.html", {"error": "Missing token.", "success": False})
    token_hash = auth_helpers.hash_token(token)
    ver = db.query(EmailVerification).filter(EmailVerification.token_hash == token_hash).first()
    if not ver or ver.used_at is not None:
        return templates.TemplateResponse(request, "verify.html", {"error": "Invalid or expired link.", "success": False})
    if ver.expires_at < datetime.now(timezone.utc):
        return templates.TemplateResponse(request, "verify.html", {"error": "Link expired.", "success": False})
    ver.used_at = datetime.now(timezone.utc)
    user = db.query(User).filter(User.id == ver.user_id).first()
    if user:
        user.email_verified = True
    db.commit()
    return templates.TemplateResponse(request, "verify.html", {"error": None, "success": True})


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
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "sessions": sessions,
            "current_session_id": str(session.id) if session else None,
            "csrf_token": session.csrf_token if session else "",
        },
    )


# --- API endpoints ---

@router.post("/auth/signup")
async def signup(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: DBSession = Depends(get_db),
):
    ip = _client_ip(request)
    auth_helpers.check_rate_limit("signup", ip)

    email_norm = auth_helpers.normalize_email(email)

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

    # Check if user exists — but return generic success either way
    existing = db.query(User).filter(User.email == email_norm).first()
    if existing:
        # Don't reveal existence. If unverified, resend verification.
        if not existing.email_verified:
            token = auth_helpers.generate_token()
            ver = EmailVerification(
                user_id=existing.id,
                token_hash=auth_helpers.hash_token(token),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            db.add(ver)
            db.commit()
            email_helpers.send_verification_email(existing.email, token)
        return JSONResponse({"message": GENERIC_SIGNUP}, status_code=200)

    user = User(
        email=email_norm,
        email_verified=False,
        password_hash=auth_helpers.hash_password(password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = auth_helpers.generate_token()
    ver = EmailVerification(
        user_id=user.id,
        token_hash=auth_helpers.hash_token(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(ver)
    db.commit()
    email_helpers.send_verification_email(user.email, token)
    return JSONResponse({"message": GENERIC_SIGNUP}, status_code=201)


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
    user = db.query(User).filter(User.email == email_norm).first()

    # Generic error — don't reveal whether email exists or password wrong
    if not user or not user.password_hash or not auth_helpers.verify_password(password, user.password_hash):
        return JSONResponse({"error": "Invalid email or password."}, status_code=401)

    if not user.email_verified:
        return JSONResponse(
            {"error": "Please verify your email before logging in. Check your inbox for a verification link."},
            status_code=403,
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

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
        auth_helpers.validate_csrf(request, session)
        auth_helpers.revoke_session(db, session)
    response = JSONResponse({"message": "Logged out."})
    _clear_session_cookie(response)
    return response


@router.post("/auth/forgot")
async def forgot(
    request: Request,
    email: str = Form(...),
    db: DBSession = Depends(get_db),
):
    ip = _client_ip(request)
    auth_helpers.check_rate_limit("forgot", ip)

    email_norm = auth_helpers.normalize_email(email)
    user = db.query(User).filter(User.email == email_norm).first()
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
        email_helpers.send_password_reset_email(user.email, token)
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

    token_hash = auth_helpers.hash_token(token)
    reset = db.query(PasswordReset).filter(PasswordReset.token_hash == token_hash).first()
    if not reset or reset.used_at is not None:
        return JSONResponse({"error": "Invalid or expired reset link."}, status_code=400)
    if reset.expires_at < datetime.now(timezone.utc):
        return JSONResponse({"error": "Reset link expired."}, status_code=400)

    reset.used_at = datetime.now(timezone.utc)
    user = db.query(User).filter(User.id == reset.user_id).first()
    if not user:
        return JSONResponse({"error": "Invalid reset link."}, status_code=400)

    user.password_hash = auth_helpers.hash_password(new_password)
    db.commit()

    # Revoke ALL sessions (including current) — password reset = security event
    auth_helpers.revoke_all_sessions(db, user.id)

    return JSONResponse({"message": "Password reset. Please log in with your new password."}, status_code=200)


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
async def revoke_session(request: Request, session_id: str, db: DBSession = Depends(get_db)):
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    auth_helpers.validate_csrf(request, session)

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
    auth_helpers.validate_csrf(request, session)
    auth_helpers.revoke_all_sessions(db, session.user_id, except_session_id=session.id)
    return {"message": "All other sessions revoked."}


# --- OAuth ---

@router.get("/auth/google")
async def google_login(request: Request):
    state = oauth_helpers.generate_oauth_state()
    # Store state in session cookie (simple, no server session needed yet)
    url = oauth_helpers.get_google_auth_url(state)
    response = RedirectResponse(url, status_code=303)
    response.set_cookie("oauth_state", state, httponly=True, secure=True, samesite="lax", max_age=600)
    response.set_cookie("oauth_action", "login", httponly=True, secure=True, samesite="lax", max_age=600)
    return response


@router.get("/auth/google/callback")
async def google_callback(request: Request, code: str = "", state: str = "", db: DBSession = Depends(get_db)):
    # Validate state (CSRF)
    stored_state = request.cookies.get("oauth_state")
    if not state or not stored_state or state != stored_state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code.")

    try:
        tokens = await oauth_helpers.exchange_google_code(code)
        userinfo = await oauth_helpers.get_google_userinfo(tokens["access_token"])
    except Exception:
        raise HTTPException(status_code=400, detail="OAuth exchange failed.")

    # Validate email_verified from Google
    if not userinfo.get("email_verified"):
        raise HTTPException(status_code=400, detail="Google email not verified.")

    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name")
    if not google_id:
        raise HTTPException(status_code=400, detail="Missing Google user ID.")

    # Check if linking (user already logged in)
    current_session = auth_helpers.get_session_from_cookie(db, request)
    action = request.cookies.get("oauth_action", "login")

    if current_session and action == "link":
        # Explicit linking flow — user is logged in and confirmed
        try:
            oauth_helpers.link_oauth_to_user(db, current_session.user, "google", google_id, email)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        response = RedirectResponse("/settings", status_code=303)
        response.delete_cookie("oauth_state")
        response.delete_cookie("oauth_action")
        return response

    # Login/signup flow — new OAuth identity = new account (no email matching)
    user, _ = oauth_helpers.find_or_create_oauth_user(db, "google", google_id, email, name)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    session, raw_token = auth_helpers.create_session(
        db, user.id, ip_address=_client_ip(request), user_agent=request.headers.get("User-Agent")
    )
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, raw_token)
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_action")
    return response


@router.get("/auth/github")
async def github_login(request: Request):
    state = oauth_helpers.generate_oauth_state()
    url = oauth_helpers.get_github_auth_url(state)
    response = RedirectResponse(url, status_code=303)
    response.set_cookie("oauth_state", state, httponly=True, secure=True, samesite="lax", max_age=600)
    response.set_cookie("oauth_action", "login", httponly=True, secure=True, samesite="lax", max_age=600)
    return response


@router.get("/auth/github/callback")
async def github_callback(request: Request, code: str = "", state: str = "", db: DBSession = Depends(get_db)):
    stored_state = request.cookies.get("oauth_state")
    if not state or not stored_state or state != stored_state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code.")

    try:
        access_token = await oauth_helpers.exchange_github_code(code)
        gh_user = await oauth_helpers.get_github_user(access_token)
        email = await oauth_helpers.get_github_primary_verified_email(access_token)
    except Exception:
        raise HTTPException(status_code=400, detail="OAuth exchange failed.")

    github_id = str(gh_user.get("id"))
    if not github_id:
        raise HTTPException(status_code=400, detail="Missing GitHub user ID.")
    if not email:
        raise HTTPException(
            status_code=400,
            detail="No verified primary email on GitHub. Please verify an email on GitHub first.",
        )

    name = gh_user.get("name") or gh_user.get("login")

    current_session = auth_helpers.get_session_from_cookie(db, request)
    action = request.cookies.get("oauth_action", "login")

    if current_session and action == "link":
        try:
            oauth_helpers.link_oauth_to_user(db, current_session.user, "github", github_id, email)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        response = RedirectResponse("/settings", status_code=303)
        response.delete_cookie("oauth_state")
        response.delete_cookie("oauth_action")
        return response

    user, _ = oauth_helpers.find_or_create_oauth_user(db, "github", github_id, email, name)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    session, raw_token = auth_helpers.create_session(
        db, user.id, ip_address=_client_ip(request), user_agent=request.headers.get("User-Agent")
    )
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, raw_token)
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_action")
    return response


@router.get("/auth/link/{provider}")
async def oauth_link_start(request: Request, provider: str, db: DBSession = Depends(get_db)):
    """Start OAuth linking flow — requires logged-in user."""
    session = auth_helpers.get_session_from_cookie(db, request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if provider not in ("google", "github"):
        raise HTTPException(status_code=400, detail="Unsupported provider.")

    state = oauth_helpers.generate_oauth_state()
    if provider == "google":
        url = oauth_helpers.get_google_auth_url(state)
    else:
        url = oauth_helpers.get_github_auth_url(state)
    response = RedirectResponse(url, status_code=303)
    response.set_cookie("oauth_state", state, httponly=True, secure=True, samesite="lax", max_age=600)
    response.set_cookie("oauth_action", "link", httponly=True, secure=True, samesite="lax", max_age=600)
    return response
