"""Issue #57: site copy and policies match actual data handling.

- No page claims results storage is a future feature.
- /privacy, /terms, /support serve 200.
- Privacy/terms/support are reachable from the signup and credits pages.
"""
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"
STALE = "planned for a future release"


def test_no_future_release_claims_in_templates(auth_env):
    for name in ["index.html", "signup.html", "pricing.html",
                 "reports.html", "report.html", "login.html", "settings.html"]:
        path = TEMPLATES / name
        if path.exists():
            assert STALE not in path.read_text(), name


def test_legal_pages_serve(auth_env):
    for page in ["/privacy", "/terms", "/support"]:
        resp = auth_env.client.get(page)
        assert resp.status_code == 200, page
        assert "<title>" in resp.text


def test_signup_and_credits_link_legal_pages(auth_env):
    for page in ["/signup", "/credits"]:
        resp = auth_env.client.get(page)
        assert resp.status_code == 200, page
        for href in ['href="/privacy"', 'href="/terms"', 'href="/support"']:
            assert href in resp.text, f"{page} missing {href}"


def test_home_and_privacy_state_seven_day_retention(auth_env):
    home = auth_env.client.get("/")
    assert home.status_code == 200
    assert "7 days" in home.text
    privacy = auth_env.client.get("/privacy")
    assert "7 days" in privacy.text
    assert "Operational request logs" in privacy.text
