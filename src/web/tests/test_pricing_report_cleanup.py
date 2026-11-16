"""Pricing/Report cleanup (founder direction 2026-11-16).

Four directives: (1) the "Paid by card from…" line leaves the Pricing
cards; (2) the "What happened to credits?" FAQ entry leaves Pricing;
(3) branding moves from the per-report Report-page form to an
ACCOUNT-level Branding profile on Settings; (4) the "Free" tag leaves
every export button (exports themselves stay free).

Teeth discipline: the new-behaviour tests FAIL on the pre-build tree
(3aff121f — pack-note line present, credits FAQ present, per-report
branding routes live, no /settings/branding, Free tags rendered) and
pass on the built tree. The stateful sequences follow Standing speed
change 2: mutate through one surface (Settings), observe through the
others (report band, generated PDFs, replay behaviour).
"""

import uuid

from test_issue162_brief import _pdf_text
from test_issue163_branding import _make_deep_dive, _png, _post_branding
from test_structured_export_e2e import _create_result, _setup


# --- 1+2: Pricing copy -------------------------------------------------


def test_pricing_cards_have_no_paid_by_card_line(auth_env):
    _setup(auth_env)
    page = auth_env.client.get("/credits")
    assert page.status_code == 200
    assert "Paid by card from" not in page.text
    # The line renders only for ready products (live Stripe prices),
    # which the test env does not configure — pin the removal at the
    # template source too, so the teeth do not depend on readiness.
    from pathlib import Path
    tpl = (Path(__file__).resolve().parents[1] / "app" / "templates"
           / "pricing.html").read_text()
    assert "Paid by card from" not in tpl
    assert "report page{% else %}quote step" not in tpl
    # The four offer cards and their facts are unchanged.
    for sku in ("investigation_report", "compare", "batch",
                "large_file_analysis"):
        assert f'data-product="{sku}"' in page.text
    assert "$9" in page.text and "$5" in page.text
    assert "The full Investigation Report for one analyzed log" \
        in page.text
    assert "Compare two logs (before / after)" in page.text
    assert "Analyze 2–5 log files together" in page.text
    assert "up to 100 MB / 500,000 lines" in page.text


def test_pricing_faq_has_no_credits_migration_entry(auth_env):
    _setup(auth_env)
    page = auth_env.client.get("/credits")
    assert page.status_code == 200
    assert "What happened to credits?" not in page.text
    assert "Credits are retired" not in page.text
    # Sibling FAQ entries and pricing facts survive.
    assert "How much does a PDF export cost?" in page.text
    assert "Can I get a refund?" in page.text
    assert "Do I need an account to use StackSift?" in page.text


# --- 4: export buttons ---------------------------------------------------


def test_export_buttons_have_no_free_tag(auth_env):
    _email, _uid, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    assert "s1-free-tag" not in page.text
    assert "Export PDF" in page.text
    # Behaviour unchanged: the exports still serve, free.
    pdf = auth_env.client.post(f"/reports/{rid}/pdf",
                               data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"


def test_deep_dive_export_buttons_have_no_free_tag(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert page.status_code == 200
    assert "s1-free-tag" not in page.text
    assert "Free</span>" not in page.text


# --- 3: branding surface move --------------------------------------------


def test_report_page_has_no_branding_form(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert page.status_code == 200
    assert "branding-panel" not in page.text
    assert 'action="/settings/branding"' not in page.text
    assert "Save branding" not in page.text


def test_old_per_report_branding_routes_are_gone(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = auth_env.client.post(
        f"/reports/{dd_id}/branding",
        data={"csrf_token": csrf, "business_name": "Acme"})
    assert r.status_code in (404, 405)
    r = auth_env.client.post(
        f"/reports/{dd_id}/branding/clear", data={"csrf_token": csrf})
    assert r.status_code in (404, 405)
    r = auth_env.client.get(f"/reports/{dd_id}/branding/logo")
    assert r.status_code in (404, 405)


def test_settings_renders_branding_profile_group(auth_env):
    _setup(auth_env)
    page = auth_env.client.get("/settings")
    assert page.status_code == 200
    text = page.text
    # Design order: 01 Account, 02 Branding profile, 03 Purchases,
    # 04 Report Access.
    order = [text.index(f'data-s4-num="{n}"')
             for n in ("01", "02", "03", "04")]
    assert order == sorted(order)
    assert 'data-s4-group="branding"' in text
    assert "Branding profile" in text
    assert "Included with every paid report" in text
    assert 'action="/settings/branding"' in text
    assert "The “Prepared with stacksift.” attribution always " \
           "remains on paid reports." in text
    for field in ("business_name", "report_title", "client_name",
                  "accent", "logo"):
        assert f'name="{field}"' in text


def test_account_branding_flows_to_band_and_pdfs(auth_env):
    """The stateful core: save in Settings -> the SAME account's
    reports (band + PDFs) carry it; another account's do not; clear
    in Settings -> later PDFs are unbranded."""
    _email, user_id, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = _post_branding(auth_env, csrf, data={
        "business_name": "Northwind Consulting",
        "client_name": "Payments platform team",
        "report_title": "Incident Investigation Report",
        "accent": "#123456"}, logo=_png())
    assert r.status_code == 200, r.text[:300]
    # Settings re-renders with the saved values.
    settings = auth_env.client.get("/settings")
    assert 'value="Northwind Consulting"' in settings.text
    assert 'value="Incident Investigation Report"' in settings.text
    # The report page band carries the account branding + account logo.
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert "Northwind Consulting" in page.text
    assert "Prepared for: Payments platform team" in page.text
    assert "/settings/branding/logo" in page.text
    # A generated PDF carries it.
    pdf = auth_env.client.post(f"/reports/{dd_id}/pdf",
                               data={"csrf_token": csrf})
    assert pdf.status_code == 200
    text = _pdf_text(pdf.content)
    assert "Northwind Consulting" in text
    assert "Incident Investigation Report" in text
    # A SECOND report of the SAME account carries it too (account
    # level, not per-report): a second source + redemption, same user.
    from product_seed import seed_entitlement_for_source
    rid2 = _create_result(auth_env, user_id, "second.log")
    seed_entitlement_for_source(auth_env.sessions, rid2)
    gen = auth_env.client.post(f"/reports/{rid2}/deep-dive",
                               data={"csrf_token": csrf})
    assert gen.status_code == 200, gen.text[:300]
    dd2 = gen.json()["analysis_result_id"]
    pdf2 = auth_env.client.post(f"/reports/{dd2}/pdf",
                                data={"csrf_token": csrf})
    assert pdf2.status_code == 200
    assert "Northwind Consulting" in _pdf_text(pdf2.content)
    # Clear in Settings -> subsequent PDFs (either report) unbranded.
    r = auth_env.client.post("/settings/branding/clear",
                             data={"csrf_token": csrf})
    assert r.status_code == 200
    pdf3 = auth_env.client.post(f"/reports/{dd2}/pdf",
                                data={"csrf_token": csrf})
    assert pdf3.status_code == 200
    assert "Northwind Consulting" not in _pdf_text(pdf3.content)


def test_account_branding_does_not_leak_across_accounts(auth_env):
    """Isolation: account A's branding never appears on account B's
    reports (the row is keyed to the owner, not the report)."""
    _email_a, _uid_a, _rid_a, dd_a, csrf_a = _make_deep_dive(auth_env)
    _post_branding(auth_env, csrf_a,
                   data={"business_name": "Account A Co"})
    pdf_a = auth_env.client.post(f"/reports/{dd_a}/pdf",
                                 data={"csrf_token": csrf_a})
    assert "Account A Co" in _pdf_text(pdf_a.content)
    # A second account with its own paid report (fixture signs the
    # client in as B).
    _email_b, _uid_b, _rid_b, dd_b, csrf_b = _make_deep_dive(auth_env)
    page_b = auth_env.client.get(f"/reports/{dd_b}")
    assert "Account A Co" not in page_b.text
    pdf_b = auth_env.client.post(f"/reports/{dd_b}/pdf",
                                 data={"csrf_token": csrf_b})
    assert pdf_b.status_code == 200
    assert "Account A Co" not in _pdf_text(pdf_b.content)


def test_account_branding_survives_report_expiry(auth_env):
    """Account semantics: branding is the account's, not a report's —
    expiring the report the owner happened to be viewing does not
    touch it (the retired per-report 410 premise, inverted)."""
    from datetime import datetime, timedelta, timezone

    from app import models
    _email, user_id, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, csrf, data={"business_name": "Acme"})
    db = auth_env.sessions()
    try:
        row = db.get(models.Result, uuid.UUID(str(dd_id)))
        row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    finally:
        db.close()
    settings = auth_env.client.get("/settings")
    assert 'value="Acme"' in settings.text
    logo = auth_env.client.get("/settings/branding/logo")
    assert logo.status_code == 404  # no logo stored; route itself live
