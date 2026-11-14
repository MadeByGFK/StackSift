"""Issue #170 S4: Settings-surface design-alignment port.

Spec v1 Decision 10 + the Settings port plan, as amended by spec v2
amendments A7 (shared-CSS coupling: surface-scoped styles +
nonported-surface check) and A8 (teeth discipline).

Mapping built here (every live section maps; nothing is added or
removed functionally):
  01 Account       <- live Account block + Connected accounts +
                      Active sessions, regrouped (remake S01)
  02 Credits       <- live Credits section (copy and /credits/balance
                      behaviour untouched) + Purchase history
                      [Phase C: replaced by 02 Purchases — see the
                      PREMISE CHANGED notes in the tests below]
  03 Report Access <- live Report Access (remake S03)
The remake's S02 branding-profile form is EXCLUDED (Decision 10):
per-report branding is #163, a saved profile is M3. Its "PNG or SVG"
logo copy must never appear.

Teeth discipline (A8): tests asserting the NEW numbered-group
structure (data-s4-group wrappers, head order, regrouped order, the
.s4- CSS block) FAIL on the base tree (f333f38f) for structural
reasons and pass on the built tree. Tests pinning pre-existing
behaviour verbatim (form/endpoint parity, credit copy, no-branding,
no-charging) are regression gates — they pass on both trees and are
labelled as such; a gate is not teeth.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from app import auth
from app.main import templates
from app.models import Consent, CreditLedger, Operation, User

APP = Path(__file__).resolve().parents[1] / "app"
CSS = (APP / "static" / "style.css").read_text()


def _session(sid, agent="Test Browser", current=False):
    return SimpleNamespace(
        id=sid, user_agent=agent, ip_address="127.0.0.1",
        created_at=datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc))


def _ctx(**overrides):
    user = SimpleNamespace(
        email="owner@example.com", display_name="Owner",
        email_verified=True)
    ctx = {
        "user": user, "current_user": user,
        "sessions": [_session("sess-1"), _session("sess-2", "Phone")],
        "current_session_id": "sess-1",
        "csrf_token": "csrf-test",
        "linked_providers": set(),
        "balance_summary": {"balance": 7, "eligible": 7},
        "purchases": [SimpleNamespace(
            pack_id="starter", credits=10,
            completed_at=datetime(2026, 1, 3, 4, 5,
                                  tzinfo=timezone.utc))],
        "pack_names": {"starter": "Starter pack"},
        "share_links": [{
            "id": "share-1", "report": "test.log", "format": "txt",
            "created_at": datetime(2026, 1, 4, 5, 6,
                                   tzinfo=timezone.utc),
            "url": "https://example.test/s/tok123",
        }],
    }
    ctx.update(overrides)
    return ctx


def _render(**overrides):
    return templates.env.get_template("settings.html").render(
        **_ctx(**overrides))


def _group_segment(html, group):
    start = html.index(f'data-s4-group="{group}"')
    nxt = html.find('data-s4-group="', start + 10)
    return html[start:] if nxt == -1 else html[start:nxt]


# --- Numbered-group structure (TEETH) -------------------------------------


def test_s4_numbered_groups_in_order_with_live_mapping():
    html = _render()
    nums = [html.index(f'data-s4-num="{n}"') for n in ("01", "02", "03")]
    assert nums == sorted(nums), nums
    # PREMISE CHANGED (#164 Phase C, Decision 9): §02 Credits is
    # §02 Purchases — completed product purchases, no balance.
    for num, label in (("01", "Account"), ("02", "Purchases"),
                       ("03", "Report Access")):
        assert f'<span class="s4-section-num" aria-hidden="true">' \
               f'{num}</span>' in html
        assert f'<span class="s4-section-label">{label}</span>' in html
    account = _group_segment(html, "account")
    # Remake S01 mapping: Account block + sessions + connected
    # accounts regrouped under 01 (spec v1 Settings mapping).
    assert "Account settings" in account
    assert "owner@example.com" in account
    assert "Connected accounts" in account
    assert "Active sessions" in account
    assert 'action="/auth/link/google"' in account
    assert 'action="/auth/link/github"' in account
    assert "revokeSession('sess-2')" in account
    assert "Log out all other devices" in account
    credits = _group_segment(html, "purchases")
    assert "Your current balance:" not in credits
    assert "Buy credits" not in credits
    assert 'id="purchase-history"' in credits
    assert "Purchase history" in credits
    assert "Per-report purchases on this account." in credits
    access = _group_segment(html, "report-access")
    assert 'id="report-access"' in access
    assert "Report Access" in access
    assert 'data-share-id="share-1"' in access


def test_s4_regroup_moves_sessions_and_connected_before_purchases():
    """Regrouping teeth: on the base tree Credits precedes Connected
    accounts / Active sessions; the port places them under 01.
    PREMISE CHANGED (#164 Phase C): the following group is the
    Purchases group (formerly Credits)."""
    html = _render()
    assert html.index("Connected accounts") < html.index(
        'data-s4-group="purchases"')
    assert html.index("Active sessions") < html.index(
        'data-s4-group="purchases"')
    assert html.index('id="purchase-history"') < html.index(
        'data-s4-group="report-access"')


def test_s4_css_block_is_settings_scoped():
    """A7 teeth: the S4 block exists in style.css and every selector
    in it is .s4- scoped (no shared selector is restyled)."""
    marker = "Issue #170 S4"
    assert marker in CSS
    block = CSS[CSS.index(marker):]
    selectors = re.findall(r"([^{}]+)\{", block)
    assert selectors, "no rules in the S4 block"
    for sel in selectors:
        assert ".s4" in sel, f"unscoped selector in S4 block: {sel!r}"
    assert ".s4-section-num" in block
    assert "var(--accent)" in block and "var(--font-code)" in block


# --- Parity: forms / endpoints / JS hooks (regression gates) ---------------


def test_s4_parity_all_base_forms_endpoints_and_hooks():
    html = _render()
    actions = re.findall(r'<form[^>]*action="([^"]+)"', html)
    # PREMISE CHANGED (fidelity S4-G2): §01 gains the design's
    # in-group Log out form, so /auth/logout appears twice (header
    # nav + field row); endpoints are otherwise unchanged.
    assert actions == ["/auth/logout", "/auth/logout",
                       "/auth/link/google", "/auth/link/github"], actions
    # CSRF field present inside every form (logout + both link
    # forms; the shared auth_form_script include adds its own field
    # elsewhere on the page, exactly as on the base tree).
    for form in re.findall(r"<form.*?</form>", html, re.S):
        assert 'name="csrf_token"' in form, form[:120]
    # JS endpoints / hooks byte-identical to base behaviour.
    assert "fetch(`/auth/sessions/${id}/revoke`" in html
    assert 'fetch("/auth/sessions/revoke-all"' in html
    assert "fetch('/settings/report-access/' + " in html
    assert "share-access-copy" in html and "share-access-revoke" in html
    assert "btn.closest('.report-access-row')" in html
    # Header/nav invariants (gates; #79/#159 class of regression).
    assert '<a href="/" class="logo">stacksift<span>.</span></a>' in html
    assert 'aria-controls="site-nav"' in html
    assert "nav-toggle" in html


def test_s4_purchases_copy_verbatim_no_balance():
    """PREMISE CHANGED (#164 Phase C, Decision 9): the §02 Credits
    group is replaced with Purchases — completed product purchases
    (name / $ amount / date), the Pricing link, and NO balance,
    Buy-credits action, or pack copy anywhere in the group."""
    purchase = SimpleNamespace(
        name="Investigation Report", amount_cents=900,
        completed_at=datetime(2026, 1, 3, 4, 5, tzinfo=timezone.utc))
    html = _render(product_purchases=[purchase])
    assert "Purchase history" in html
    assert "Per-report purchases on this account." in html
    assert "Investigation Report — $9.00" in html
    assert "2026-01-03 04:05 UTC" in html
    assert '<a href="/credits">Pricing</a>' in html
    assert "Your current balance:" not in html
    assert ">7 credits</strong>" not in html
    assert "Buy credits" not in html
    assert "One-time credit pack purchases on this account." not in html
    assert "Starter pack — 10 credits" not in html
    assert "No purchases yet." in _render(product_purchases=[])


def test_s4_report_access_and_empty_states_verbatim():
    html = _render()
    assert "test.log — TXT" in html
    assert "https://example.test/s/tok123" in html
    assert 'class="share-access-link"' in html
    empty = _render(share_links=[])
    assert "No active share links." in empty
    linked = _render(linked_providers={"google"})
    assert "✓ Connected" in linked
    assert 'action="/auth/link/google"' not in linked
    assert 'action="/auth/link/github"' in linked


# --- Decision 10 exclusions (gates) -----------------------------------------


def test_s4_no_branding_profile_form_and_no_svg_logo_copy():
    html = _render()
    assert "Branding profile" not in html
    assert "Drop a PNG" not in html
    assert "SVG" not in html
    assert 'type="file"' not in html
    assert "Logo (" not in html
    assert "business_name" not in html


# --- Live route: structure (teeth) + no-charging (gate) ---------------------


def _login_user(env, email="owner@example.com"):
    with env.sessions() as db:
        user = User(email=email, email_verified=True,
                    password_hash=auth.hash_password("Str0ng!Passw0rd"))
        db.add(user)
        db.commit()
        session, raw = auth.create_session(db, user.id)
        csrf = session.csrf_token
    env.client.cookies.set(auth.SESSION_COOKIE, raw,
                           domain="testserver.local", path="/")
    env.client.headers["X-CSRF-Token"] = csrf
    return csrf


def _row_counts(env):
    with env.sessions() as db:
        return (db.query(Operation).count(),
                db.query(Consent).count(),
                db.query(CreditLedger).count())


def test_s4_live_settings_page_groups_and_no_charging_rows(auth_env):
    _login_user(auth_env)
    before = _row_counts(auth_env)
    page = auth_env.client.get("/settings")
    assert page.status_code == 200
    # Teeth on the live route: the numbered groups render.
    # PREMISE CHANGED (#164 Phase C): §02 is "purchases", not "credits".
    for marker in ('data-s4-group="account"', 'data-s4-group="purchases"',
                   'data-s4-group="report-access"'):
        assert marker in page.text, marker
    assert 'data-s4-group="credits"' not in page.text
    assert "Your current balance" not in page.text
    # Gate: rendering Settings creates no charging rows (Decision 12).
    auth_env.client.get("/settings")
    assert _row_counts(auth_env) == before


def test_s4_nonported_surfaces_still_render(auth_env):
    """A7 nonported-surface check: pricing (the /credits route),
    auth, Analyze, and My Reports render unchanged and carry no
    S4 markup; the responsive nav stays intact on each. The sample
    surface is checked by direct template render below (its route
    needs the #159 fixtures, not the bare auth_env)."""
    _login_user(auth_env)
    for path in ("/", "/login", "/credits", "/reports"):
        page = auth_env.client.get(path)
        assert page.status_code == 200, (path, page.status_code)
        assert "s4-section" not in page.text, path
        assert "s4-group" not in page.text, path
        assert '<a href="/" class="logo">stacksift<span>.</span></a>' \
            in page.text, path
        assert 'class="nav-toggle"' in page.text, path


def test_s4_sample_template_carries_no_s4_markup():
    """A7: the sample (deep_dive_report.html, is_sample) is a
    nonported surface for S4 — it renders with no S4 markup and
    its nav stays intact."""
    from app import deep_dive as dd
    from test_issue162_brief import _sample_artifact
    projection = dd.public_projection(_sample_artifact())
    html = templates.env.get_template("deep_dive_report.html").render(
        analysis_projection=projection, filename="sample.log",
        is_sample=True,
        branding={"business_name": "WellInstance",
                  "client_name": None, "report_title": None,
                  "accent": None, "logo_url": None})
    assert "s4-section" not in html and "s4-group" not in html
    assert "SAMPLE" in html
