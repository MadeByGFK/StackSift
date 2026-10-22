"""Issue #79: header wordmark standardization + mobile-only hamburger nav.

Structural checks (in the style of test_issue59_a11y.py) across every
template that carries the site header, plus TestClient renders for both
auth states. Collapsed-menu behavior in a real viewport (<=768px), the
credits badge staying in the header bar, and logout from inside the menu
are covered by test_issue79_header_browser.py.
"""
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
TEMPLATES = APP / "templates"
CSS = (APP / "static" / "style.css").read_text()

# Every template carrying the site header: the 13 shared-`header.top`
# pages plus reports.html (its own header family, same patterns).
HEADER_TEMPLATES = [
    "forgot.html", "index.html", "login.html", "oauth_error.html",
    "pricing.html", "privacy.html", "report.html", "reports.html",
    "reset.html", "settings.html", "signup.html", "support.html",
    "terms.html", "verify.html",
]
LOGO_ANCHOR = '<a href="/" class="logo">stacksift<span>.</span></a>'
TOGGLE_RE = re.compile(
    r'<button class="nav-toggle" type="button" aria-expanded="false" '
    r'aria-controls="site-nav" aria-label="Menu">'
)


def _read(name):
    return (TEMPLATES / name).read_text()


def test_every_header_template_uses_anchor_logo():
    for name in HEADER_TEMPLATES:
        html = _read(name)
        assert LOGO_ANCHOR in html, name
        assert '<div class="logo">' not in html, name


def test_every_header_template_has_toggle_and_nav_id():
    for name in HEADER_TEMPLATES:
        html = _read(name)
        assert TOGGLE_RE.search(html), name
        assert '<nav class="nav-links" id="site-nav">' in html, name


def test_every_header_template_includes_nav_script():
    for name in HEADER_TEMPLATES:
        assert "nav_script.html" in _read(name), name


def test_paid_consent_has_no_header_to_convert():
    html = _read("paid_consent.html")
    assert 'class="logo"' not in html
    assert "nav-toggle" not in html


def test_shared_css_canonical_logo_rule():
    assert ".logo { font-size: 20px; font-weight: 700; letter-spacing: -.02em;" in CSS
    assert ".logo span { color: var(--accent); }" in CSS


def test_shared_css_nav_rule_cannot_shrink_the_logo():
    # The old unscoped `.top a` rule is gone; 14px now reaches nav links only.
    assert not re.search(r"^\.top a \{", CSS, flags=re.M)
    assert ".top .nav-links a {" in CSS
    assert "font-size: 14px" in CSS


def test_shared_css_mobile_nav_rules():
    assert ".nav-toggle { display: none;" in CSS
    block = CSS[CSS.index("@media (max-width: 768px)"):]
    assert ".nav-toggle { display: inline-flex;" in block
    assert ".top .nav-links { display: none;" in block
    assert ".top .nav-links.open { display: flex; }" in block


def test_reports_local_css_keeps_canonical_logo_and_gains_mobile_rules():
    html = _read("reports.html")
    # Pre-existing canonical rule untouched — the page renders as before.
    assert ".logo{font-size:20px;font-weight:700;letter-spacing:-.02em}" in html
    assert ".nav-toggle{display:none;" in html
    block = html[html.index("@media (max-width:768px)"):]
    assert ".nav .nav-links{display:none;" in block
    assert ".nav .nav-links.open{display:flex}" in block


def test_nav_script_behaviors():
    js = _read("nav_script.html")
    for needle in (
        "aria-expanded",
        "Escape",
        "classList.toggle('open'",
        "matchMedia('(max-width: 768px)')",
        "closest('a')",
        'form[action="/auth/logout"]',
    ):
        assert needle in js, needle


def test_auth_script_places_badge_in_bar_on_mobile():
    js = _read("auth_form_script.html")
    assert "placeBadge" in js
    assert "document.querySelector('.nav-toggle')" in js
    # Desktop placement is still the original insert-before-logout-form.
    assert "logoutForm.parentNode.insertBefore(badge, logoutForm)" in js


def test_rendered_anonymous_pages_have_new_header(auth_env):
    for path in ("/", "/login", "/credits", "/privacy"):
        page = auth_env.client.get(path)
        assert page.status_code == 200, path
        assert LOGO_ANCHOR in page.text, path
        assert TOGGLE_RE.search(page.text), path
        assert '<nav class="nav-links" id="site-nav">' in page.text, path
        # Anonymous menu contents are unchanged.
        assert "Log in" in page.text and "Sign up" in page.text, path


def test_rendered_logged_in_header_keeps_menu_contents(auth_env, monkeypatch):
    # Page rendering resolves the current user through app.db.SessionLocal
    # (not the get_db dependency) and only when DATABASE_URL is set — point
    # both at the test database, as in test_issue67_notify.py.
    import app.db as db_module

    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setattr(db_module, "SessionLocal", auth_env.sessions)

    from app.models import User

    email = "nav79@example.com"
    auth_env.client.post("/auth/signup", data={"email": email, "password": "SecurePass123!"})
    db = auth_env.sessions()
    user = db.query(User).filter(User.email == email).first()
    user.email_verified = True
    db.commit()
    db.close()
    resp = auth_env.client.post("/auth/login", data={"email": email, "password": "SecurePass123!"})
    assert resp.status_code == 200, resp.text

    # The shared client's jar does not retain the session cookie; like the
    # phase-1 tests, carry the login response cookies into a fresh client.
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app, base_url="https://testserver", cookies=dict(resp.cookies))
    page = client.get("/")
    assert page.status_code == 200
    assert LOGO_ANCHOR in page.text
    assert TOGGLE_RE.search(page.text)
    # Logged-in menu contents, incl. the CSRF-carrying logout form.
    assert '<a href="/reports">My Reports</a>' in page.text
    assert '<a href="/settings">Settings</a>' in page.text
    assert 'action="/auth/logout"' in page.text
    assert 'name="csrf_token"' in page.text
