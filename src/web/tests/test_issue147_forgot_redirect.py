"""Issue #147: after 'Send reset link', return the user to the login screen.

Founder direction 2026-11-04: submitting the Forgot password form left
the user on that page with the inline generic message. Now every submit
lands on /login, which shows the same neutral notice:

- A plain (non-JS) POST /auth/forgot answers 303 to the fixed target
  /login?reset_sent=1 in ALL cases — identical status, Location, body
  and cookies whether or not the account exists, so the redirect leaks
  nothing about account existence. The reset email is still sent only
  when the account exists and has a password (internal behaviour
  unchanged; only the response changed).
- The browser flow posts via the shared auth-form JS with
  X-Requested-With: XMLHttpRequest (the logout route's split): that
  caller keeps the generic JSON contract, and the forgot form's
  data-success-url="/login?reset_sent=1" hands the browser to the same
  login URL on success.
- GET /login shows the notice ONLY for the exact fixed flag
  reset_sent=1, and the notice text is the server-side GENERIC_FORGOT
  constant — the submitted email and any free-text query value are
  never reflected, so the notice cannot be forged or injected.
- The rest of the flow is untouched: email link -> reset page -> the
  #130 confirmation modal -> OK -> /login (covered by
  test_issue130_reset_redirect, unchanged).
"""
from pathlib import Path

from app import auth as auth_helpers
from app.auth_routes import GENERIC_FORGOT
from app.models import User

TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"
FORGOT_PAGE = (TEMPLATES / "forgot.html").read_text()
LOGIN_PAGE = (TEMPLATES / "login.html").read_text()
SCRIPT = (TEMPLATES / "auth_form_script.html").read_text()

TARGET = "/login?reset_sent=1"
KNOWN = "known147@example.com"
UNKNOWN = "unknown147@example.com"


def _known_user(auth_env, email=KNOWN):
    with auth_env.sessions() as db:
        db.add(User(email=email, email_verified=True,
                    password_hash=auth_helpers.hash_password("SecurePass123!")))
        db.commit()


def _form_tag(page_html: str, action: str) -> str:
    for line in page_html.splitlines():
        if "<form" in line and f'action="{action}"' in line:
            return line
    raise AssertionError(f"no form with action={action} found")


def test_forgot_redirect_identical_for_known_and_unknown(auth_env):
    _known_user(auth_env)
    known = auth_env.client.post("/auth/forgot", data={"email": KNOWN},
                                 follow_redirects=False)
    unknown = auth_env.client.post("/auth/forgot", data={"email": UNKNOWN},
                                   follow_redirects=False)
    # Internal behaviour unchanged: a reset email went out ONLY for the
    # real account...
    assert [entry[0] for entry in auth_env.sent] == ["reset"]
    assert auth_env.sent[0][1] == KNOWN
    # ...but the responses are indistinguishable: same status, Location,
    # body and Set-Cookie — no enumeration through the redirect.
    assert known.status_code == unknown.status_code == 303
    assert known.headers["location"] == unknown.headers["location"] == TARGET
    assert known.content == unknown.content
    assert known.headers.get("set-cookie") == unknown.headers.get("set-cookie")


def test_forgot_followed_redirect_lands_on_login_with_notice(auth_env):
    _known_user(auth_env)
    for email in (KNOWN, UNKNOWN):
        resp = auth_env.client.post("/auth/forgot", data={"email": email})
        assert resp.status_code == 200
        assert str(resp.url).endswith(TARGET)
        assert "<h1>Log in</h1>" in resp.text
        assert GENERIC_FORGOT in resp.text


def test_forgot_ajax_contract_identical_and_form_hands_off_to_login(auth_env):
    # The rendered forgot form opts into the login hand-off through the
    # shared handler's established data-success-url mechanism.
    tag = _form_tag(auth_env.client.get("/forgot").text, "/auth/forgot")
    assert f'data-success-url="{TARGET}"' in tag
    assert "} else if (response.ok && form.dataset.successUrl) location.assign(form.dataset.successUrl);" in SCRIPT
    _known_user(auth_env)
    headers = {"X-Requested-With": "XMLHttpRequest"}
    known = auth_env.client.post("/auth/forgot", data={"email": KNOWN},
                                 headers=headers, follow_redirects=False)
    unknown = auth_env.client.post("/auth/forgot", data={"email": UNKNOWN},
                                   headers=headers, follow_redirects=False)
    assert known.status_code == unknown.status_code == 200
    assert known.content == unknown.content
    assert known.json() == {"message": GENERIC_FORGOT}


def test_forgot_form_static_contract():
    tag = _form_tag(FORGOT_PAGE, "/auth/forgot")
    assert f'data-success-url="{TARGET}"' in tag
    # The login template renders the (constant) notice in its success box.
    assert '{% if message %}<div class="success">{{ message }}</div>{% endif %}' in LOGIN_PAGE


def test_login_notice_only_for_the_fixed_flag(auth_env):
    flagged = auth_env.client.get("/login", params={"reset_sent": "1"})
    assert GENERIC_FORGOT in flagged.text
    assert '<div class="success">' in flagged.text
    plain = auth_env.client.get("/login")
    assert GENERIC_FORGOT not in plain.text
    # A crafted flag value neither shows nor alters the notice, and an
    # unrelated free-text parameter is never reflected into the page.
    crafted = auth_env.client.get(
        "/login",
        params={"reset_sent": "<script>alert(147)</script>",
                "notice": "crafted-notice-147"},
    )
    assert GENERIC_FORGOT not in crafted.text
    assert "alert(147)" not in crafted.text
    assert "crafted-notice-147" not in crafted.text


def test_forgot_email_input_is_never_reflected(auth_env):
    payload = 'victim@example.com"><script>alert(147)</script>'
    resp = auth_env.client.post("/auth/forgot", data={"email": payload},
                                follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == TARGET
    assert "alert(147)" not in resp.headers["location"]
    assert payload not in resp.text
    landed = auth_env.client.get(resp.headers["location"])
    assert GENERIC_FORGOT in landed.text
    assert "alert(147)" not in landed.text
    assert "victim@example.com" not in landed.text


def test_forgot_double_submit_same_redirect(auth_env):
    _known_user(auth_env)
    first = auth_env.client.post("/auth/forgot", data={"email": KNOWN},
                                 follow_redirects=False)
    second = auth_env.client.post("/auth/forgot", data={"email": KNOWN},
                                  follow_redirects=False)
    assert first.status_code == second.status_code == 303
    assert first.headers["location"] == second.headers["location"] == TARGET
    # Replay changes nothing observable; each submit still issues its
    # reset email internally, exactly as before #147.
    assert [entry[0] for entry in auth_env.sent] == ["reset", "reset"]
