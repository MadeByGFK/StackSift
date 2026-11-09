"""Issue #135: sharing rework — share the report FILE, per format.

Supersedes the #107 recipient web view: the Share popup offers
PDF / TXT / JSON / CSV; TXT is free with no unlock and no charge;
PDF/JSON/CSV require the report's #129 2-credit per-report export
unlock (no charge beyond the unlock itself); each link serves ONLY
its chosen format with the report's exact content to logged-out
holders; Settings -> Report Access lists every active link (report,
format, created time, copyable link, Revoke per link); revoke is
immediate; revoked and expired-report links serve nothing (the
existing identical unavailable response).

Cross-feature interaction cases (spec shift-left rule, enumerated):
- export unlock x share: pre-unlock denial, post-unlock creation in
  every format, no second charge, an unlock bought in one format
  unlocking share creation in all formats;
- retention/expiry x share: an active link follows an extension;
  an expired report's links (all formats) serve nothing;
- revoke x replay/idempotency: same create key + different format is
  a 409 conflict; same key + same format replays as already_shared;
  a format-scoped revoke kills only that format and its replay is a
  no-op;
- CSP / log-redaction x file serving: file responses carry the base
  share CSP + attachment disposition, and the raw token never reaches
  application logs on the new file routes.

TEETH: the pre-unlock denial tests fail on the pre-#135 tree, where
share creation ignored any format field and returned 200/created for
every request (verified by running this file against the pristine
base tree — see the PR evidence).
"""

import json
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from test_phase2b_paid_e2e import paid_env, _signup_verify_login, _http_balance  # noqa: F401
from test_report_sharing import _anon_client, _make_report, _payload, _token_from
from test_structured_export_e2e import _grant

from pdf_content import pdf_content_signature

from app import auth, credits as C, main, models as M
from app.service import render_text_report


def _create(env, rid, csrf, key, fmt=None):
    data = {"csrf_token": csrf, "idempotency_key": key}
    if fmt is not None:
        data["format"] = fmt
    return env.client.post(f"/reports/{rid}/share", data=data)


def _unlock_via_csv(env, rid, csrf):
    r = env.client.post(f"/reports/{rid}/exports/csv",
                        data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    return r


def _stored_payload(env, rid):
    with env.sessions() as db:
        result = db.get(M.Result, rid)
        return json.loads(result.storage_manifest)


def _sharing_rows(env, rid):
    with env.sessions() as db:
        return db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).all()


def _setup_unlocked(env, *, grant=10):
    _, uid, csrf = _signup_verify_login(env)
    if grant:
        _grant(env, uid, grant)
    rid = _make_report(env, uid)
    _unlock_via_csv(env, rid, csrf)
    return uid, csrf, rid


# --- format gating (the teeth) ----------------------------------------------

def test_txt_share_free_without_unlock_and_no_charge(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create(env, rid, csrf, "t135-txt-1", "txt")
    assert resp.status_code == 200, resp.text[:300]
    assert resp.json()["format"] == "txt"
    assert _http_balance(env) == 10  # no unlock bought, no charge
    with env.sessions() as db:
        assert C.is_export_unlocked(db, uid, rid) is False
    token = _token_from(resp)
    r = _anon_client().get(f"/s/{token}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")


@pytest.mark.parametrize("fmt", ["pdf", "json", "csv"])
def test_gated_formats_blocked_pre_unlock_no_link_no_charge(paid_env, fmt):
    """TEETH: on the pre-#135 tree this create returned 200/created
    (format was ignored); here it must be refused BEFORE anything is
    created or charged."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create(env, rid, csrf, f"t135-blocked-{fmt}", fmt)
    assert resp.status_code == 402, resp.text[:300]
    assert resp.json().get("code") == "export_unlock_required"
    assert resp.json().get("export_unlocked") is False
    assert _http_balance(env) == 10  # no charge for the denial
    rows = [r for r in _sharing_rows(env, rid)
            if (r.share_format or "txt") == fmt]
    assert rows == []  # no link row left behind


def test_invalid_share_format_400_and_no_link(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create(env, rid, csrf, "t135-badfmt", "docx")
    assert resp.status_code == 400, resp.text[:300]
    assert _sharing_rows(env, rid) == []


def test_gated_creation_after_unlock_charges_nothing_beyond_unlock(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked(env)
    balance_after_unlock = _http_balance(env)
    tokens = {}
    for fmt in ("pdf", "json", "csv"):
        resp = _create(env, rid, csrf, f"t135-make-{fmt}", fmt)
        assert resp.status_code == 200, (fmt, resp.text[:300])
        assert resp.json()["format"] == fmt
        tokens[fmt] = _token_from(resp)
    # Exactly the single 2-credit unlock was charged (by the CSV
    # export); share creation in every gated format charged 0 more.
    assert _http_balance(env) == balance_after_unlock
    assert len(set(tokens.values())) == 3
    rows = _sharing_rows(env, rid)
    assert sorted(r.share_format for r in rows) == ["csv", "json", "pdf"]


# --- each link serves only its format, with exact content --------------------

def test_each_link_serves_only_its_format_with_exact_content(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked(env)
    tokens = {}
    for fmt in ("txt", "pdf", "json", "csv"):
        resp = _create(env, rid, csrf, f"t135-serve-{fmt}", fmt)
        assert resp.status_code == 200, (fmt, resp.text[:300])
        tokens[fmt] = _token_from(resp)
    anon = _anon_client()
    stored = _stored_payload(env, rid)

    txt = anon.get(f"/s/{tokens['txt']}")
    assert txt.status_code == 200
    assert txt.headers["content-type"].startswith("text/plain")
    assert txt.text == render_text_report(stored)

    owner_csv = env.client.post(f"/reports/{rid}/exports/csv",
                                data={"csrf_token": csrf})
    assert owner_csv.status_code == 200
    csv_r = anon.get(f"/s/{tokens['csv']}")
    assert csv_r.status_code == 200
    assert csv_r.headers["content-type"].startswith("text/csv")
    assert csv_r.content == owner_csv.content

    owner_json = env.client.post(f"/reports/{rid}/exports/json",
                                 data={"csrf_token": csrf})
    assert owner_json.status_code == 200
    json_r = anon.get(f"/s/{tokens['json']}")
    assert json_r.status_code == 200
    assert json_r.headers["content-type"].startswith("application/json")
    assert json_r.content == owner_json.content
    assert json.loads(json_r.content) == stored

    owner_pdf = env.client.post(f"/reports/{rid}/pdf",
                                data={"csrf_token": csrf})
    assert owner_pdf.status_code == 200 and owner_pdf.content[:4] == b"%PDF"
    pdf_r = anon.get(f"/s/{tokens['pdf']}")
    assert pdf_r.status_code == 200
    assert "application/pdf" in pdf_r.headers["content-type"]
    # Issue #174: the owner export and the share serve are two
    # independent on-the-fly generations of the same report, and
    # fpdf2 embeds a per-generation /CreationDate + trailer /ID, so
    # raw bytes differ whenever the generations cross a one-second
    # boundary (the PostgreSQL-leg flake). The exact-content intent
    # is asserted at content level: identical extracted text
    # (generation furniture stripped), page count, per-page footer
    # and document title — see pdf_content.pdf_content_signature.
    # The CSV/JSON legs above stay byte-exact: those serializers are
    # deterministic and embed no timestamp or trailer ID.
    assert pdf_content_signature(pdf_r.content) == \
        pdf_content_signature(owner_pdf.content)

    # ONLY its format: the txt link does not serve the PDF subroute,
    # and no link serves another format's content type.
    assert anon.get(f"/s/{tokens['txt']}/pdf").status_code == 404
    assert anon.get(f"/s/{tokens['csv']}/pdf").status_code == 404
    assert anon.get(f"/s/{tokens['json']}/pdf").status_code == 404
    assert pdf_r.content != csv_r.content
    assert "text/plain" not in pdf_r.headers["content-type"]


# --- replay / idempotency x format -------------------------------------------

def test_create_replay_same_key_different_format_is_409(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    first = _create(env, rid, csrf, "t135-replay-1", "txt")
    assert first.status_code == 200, first.text[:300]
    # The request hash binds the format: the same key replayed for a
    # different format conflicts instead of minting a second link.
    conflict = _create(env, rid, csrf, "t135-replay-1", "csv")
    assert conflict.status_code == 409, conflict.text[:300]
    rows = _sharing_rows(env, rid)
    assert len(rows) == 1 and rows[0].share_format == "txt"


def test_create_replay_same_key_same_format_no_new_token(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    first = _create(env, rid, csrf, "t135-replay-2", "txt")
    token = _token_from(first)
    replay = _create(env, rid, csrf, "t135-replay-2", "txt")
    assert replay.status_code == 200
    assert replay.json().get("status") == "already_shared"
    assert "share_url" not in replay.json()
    assert _anon_client().get(f"/s/{token}").status_code == 200
    # A second DISTINCT create key for an already-active format is
    # also already_shared (one active link per format).
    again = _create(env, rid, csrf, "t135-replay-3", "txt")
    assert again.json().get("status") == "already_shared"
    assert len(_sharing_rows(env, rid)) == 1


# --- retention / expiry x share ----------------------------------------------

def test_expired_report_links_serve_nothing_all_formats(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked(env)
    tokens = {}
    for fmt in ("txt", "pdf", "json", "csv"):
        resp = _create(env, rid, csrf, f"t135-exp-{fmt}", fmt)
        tokens[fmt] = _token_from(resp)
    anon = _anon_client()
    for fmt, token in tokens.items():
        assert anon.get(f"/s/{token}").status_code == 200, fmt
    baseline = anon.get(f"/s/{'0' * 64}")
    assert baseline.status_code == 404
    with env.sessions() as db:
        result = db.get(M.Result, rid)
        result.expires_at = C._utcnow() - timedelta(days=1)
        db.commit()
    for fmt, token in tokens.items():
        r = anon.get(f"/s/{token}")
        assert r.status_code == 404, fmt
        assert r.content == baseline.content, fmt


def test_active_link_follows_retention_extension(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create(env, rid, csrf, "t135-ext-1", "txt")
    token = _token_from(resp)
    anon = _anon_client()
    assert anon.get(f"/s/{token}").status_code == 200
    ext = env.client.post(
        f"/reports/{rid}/retention",
        data={"csrf_token": csrf, "idempotency_key": "t135-ext-buy"})
    assert ext.status_code == 200, ext.text[:300]
    # The link keeps serving under the extended window.
    assert anon.get(f"/s/{token}").status_code == 200


# --- revoke x Settings Report Access ------------------------------------------

def _settings_html(env):
    r = env.client.get("/settings")
    assert r.status_code == 200, r.text[:300]
    return r.text


def _sharing_id_for(env, rid, fmt):
    with env.sessions() as db:
        row = db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid,
            M.ReportSharing.share_format == fmt).one()
        return str(row.id)


def test_settings_report_access_lists_and_revoke_kills_only_that_link(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked(env)
    tokens = {}
    for fmt in ("txt", "csv"):
        resp = _create(env, rid, csrf, f"t135-ra-{fmt}", fmt)
        tokens[fmt] = _token_from(resp)
    html = _settings_html(env)
    assert 'id="report-access"' in html
    assert "Report Access" in html
    assert "test.log" in html  # the report
    assert "TXT" in html and "CSV" in html  # the formats
    # Created time is rendered (format used by settings.html rows).
    with env.sessions() as db:
        row = db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid,
            M.ReportSharing.share_format == "txt").one()
        created = row.created_at.strftime("%Y-%m-%d %H:%M UTC")
    assert created in html
    # The copyable live links themselves are listed (reshare = copy).
    assert f"/s/{tokens['txt']}" in html
    assert f"/s/{tokens['csv']}" in html
    assert "share-access-revoke" in html

    # Revoke the CSV link from Settings: it dies immediately, the
    # TXT link for the same report keeps serving.
    csv_id = _sharing_id_for(env, rid, "csv")
    anon = _anon_client()
    assert anon.get(f"/s/{tokens['csv']}").status_code == 200
    r = env.client.post(
        f"/settings/report-access/{csv_id}/revoke",
        data={"csrf_token": csrf, "idempotency_key": "t135-ra-revoke-csv"})
    assert r.status_code == 200, r.text[:300]
    assert r.json() == {"status": "revoked"}
    assert anon.get(f"/s/{tokens['csv']}").status_code == 404
    assert anon.get(f"/s/{tokens['txt']}").status_code == 200
    # Replay of the same Settings revoke key is a no-op success.
    r2 = env.client.post(
        f"/settings/report-access/{csv_id}/revoke",
        data={"csrf_token": csrf, "idempotency_key": "t135-ra-revoke-csv"})
    assert r2.status_code == 200 and r2.json() == {"status": "revoked"}
    # The revoked link leaves the Report Access list.
    html2 = _settings_html(env)
    assert f"/s/{tokens['csv']}" not in html2
    assert f"/s/{tokens['txt']}" in html2


def test_settings_revoke_is_owner_only(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked(env)
    resp = _create(env, rid, csrf, "t135-ra-own", "txt")
    token = _token_from(resp)
    sharing_id = _sharing_id_for(env, rid, "txt")
    # A second user neither sees the link in Settings nor can revoke it.
    _, uid2, csrf2 = _signup_verify_login(env)
    html = _settings_html(env)
    assert f"/s/{token}" not in html
    r = env.client.post(
        f"/settings/report-access/{sharing_id}/revoke",
        data={"csrf_token": csrf2, "idempotency_key": "t135-ra-foreign"})
    assert r.status_code == 404, r.text[:300]
    assert _anon_client().get(f"/s/{token}").status_code == 200
    # Anonymous callers get 401.
    anon = _anon_client()
    r2 = anon.post(f"/settings/report-access/{sharing_id}/revoke",
                   data={"csrf_token": "x", "idempotency_key": "t135-ra-anon"})
    assert r2.status_code == 401


def test_format_scoped_revoke_kills_only_that_format(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked(env)
    tokens = {}
    for fmt in ("txt", "json"):
        resp = _create(env, rid, csrf, f"t135-frev-{fmt}", fmt)
        tokens[fmt] = _token_from(resp)
    anon = _anon_client()
    r = env.client.post(
        f"/reports/{rid}/share/revoke",
        data={"csrf_token": csrf, "idempotency_key": "t135-frev-json",
              "format": "json"})
    assert r.status_code == 200, r.text[:300]
    assert anon.get(f"/s/{tokens['json']}").status_code == 404
    assert anon.get(f"/s/{tokens['txt']}").status_code == 200


# --- popup contract ------------------------------------------------------------

def test_share_popup_offers_four_formats_with_locked_gating(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    page = env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    for value in ('value="txt"', 'value="pdf"', 'value="json"', 'value="csv"'):
        assert value in page.text, value
    assert 'name="share-format"' in page.text
    # Gated formats are shown as locked pre-unlock on the report page.
    assert "locked — export unlock required" in page.text
    assert 'data-locked="1"' in page.text
    # My Reports popup offers the same four formats.
    reports_page = env.client.get("/reports")
    assert 'name="share-format"' in reports_page.text
    # After the unlock, the report-page popup no longer marks locks.
    _unlock_via_csv(env, rid, csrf)
    page2 = env.client.get(f"/reports/{rid}")
    assert 'data-locked="1"' not in page2.text


# --- CSP / headers / log-redaction x file serving ------------------------------

def test_file_responses_carry_share_headers_and_no_cookie(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create(env, rid, csrf, "t135-hdr-1", "txt")
    token = _token_from(resp)
    anon = _anon_client()
    for r in (anon.get(f"/s/{token}"), anon.get(f"/s/{'0' * 64}")):
        assert r.headers.get("cache-control") == "private, no-store"
        assert r.headers.get("referrer-policy") == "no-referrer"
        assert "noindex" in r.headers.get("x-robots-tag", "")
        csp = r.headers.get("content-security-policy", "")
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert r.headers.get("x-frame-options") == "DENY"
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert "set-cookie" not in {k.lower() for k in r.headers.keys()}


def test_file_route_token_not_in_app_logs(paid_env, caplog):
    import logging
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create(env, rid, csrf, "t135-log-1", "txt")
    token = _token_from(resp)
    anon = _anon_client()
    with caplog.at_level(logging.DEBUG):
        assert anon.get(f"/s/{token}").status_code == 200
    for record in caplog.records:
        if record.name.startswith("httpx"):
            continue  # the test client's own request log, not the app's
        assert token not in record.getMessage()
