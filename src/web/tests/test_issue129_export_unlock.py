"""Issue #129: per-report export unlock (founder ruling 2026-11-03).

Supersedes the #105 per-format charging model: ONE 2-credit charge per
(owner, report) unlocks every format (PDF/CSV/JSON). First successful
generation in any format charges exactly 2 once; later generations /
downloads of any format charge 0; a replayed unlock never
double-charges; failure before generation charges 0 and does NOT
unlock. An export-unlocked report also counts as PDF-purchased for
the #107 share-link PDF rule (§5).

PREMISE CHANGED (issue #164 Phase C, Decision 4 / C7a): exports are
FREE for all reports — export_unlock_state returns unlocked=True
unconditionally, with no consent/admission/operation/ledger and no
balance consult. The tests below are re-based to that premise with
the same strength: "charges exactly once" becomes "charges zero, no
operation/ledger, all formats free"; insufficient-credits cases
become free successes; the share-PDF gate is gone.

UI amendment (founder, 2026-11-03): report page keeps exactly the
Export + Share buttons (Export = dropdown), no explanatory
paragraphs, Extend/Share forms off the page; My Reports rows carry
View / Export (dropdown) / Share / Extend; actions are confirmed in
a popup before any charge; Share creates the link in-page and shows
a copyable link + "Open in email".
"""

import json

import pytest

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import (
    _artifacts,
    _balance,
    _drain_signup,
    _grant,
    _ops,
    _setup,
)
from test_phase2b_reports_pdf import _create_result
from app import credits as C


def _all_export_ops(auth_env, user_id):
    return (_ops(auth_env, user_id, "pdf")
            + _ops(auth_env, user_id, "structured_export"))


def _completed_charges(auth_env, user_id):
    return [op for op in _all_export_ops(auth_env, user_id)
            if op.status == "completed"]


# --- charging core -----------------------------------------------------------

def test_pdf_first_unlocks_csv_and_json(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before
    csv_r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200, csv_r.text[:300]
    assert csv_r.headers["content-type"].startswith("text/csv")
    json_r = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert json_r.status_code == 200, json_r.text[:300]
    json.loads(json_r.content)
    # Phase C: EVERY format is free — zero charges, no export
    # operation and no ledger movement at all.
    assert _balance(auth_env, user_id) == before
    assert _completed_charges(auth_env, user_id) == []
    assert _all_export_ops(auth_env, user_id) == []
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_csv_first_unlocks_pdf_and_json(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    csv_r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200, csv_r.text[:300]
    assert _balance(auth_env, user_id) == before
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    json_r = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert json_r.status_code == 200
    # Phase C: zero charges / operations in any order.
    assert _balance(auth_env, user_id) == before
    assert _completed_charges(auth_env, user_id) == []
    assert _all_export_ops(auth_env, user_id) == []


def test_json_first_unlocks_csv_and_pdf(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    json_r = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert json_r.status_code == 200
    assert _balance(auth_env, user_id) == before
    csv_r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert csv_r.status_code == 200 and pdf.status_code == 200
    # Phase C: zero charges / operations in any order.
    assert _balance(auth_env, user_id) == before
    assert _completed_charges(auth_env, user_id) == []
    assert _all_export_ops(auth_env, user_id) == []


def test_replayed_unlock_never_double_charges(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    for _ in range(2):
        r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
        assert r.status_code == 200
    for _ in range(2):
        r = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
        assert r.status_code == 200
    r = auth_env.client.post(f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert r.status_code == 200
    # Phase C: replays charge zero and create no operation at all.
    assert _balance(auth_env, user_id) == before
    assert _completed_charges(auth_env, user_id) == []
    assert _all_export_ops(auth_env, user_id) == []


def test_failed_generation_charges_zero_and_does_not_unlock(auth_env, monkeypatch):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    from app import structured_export as se
    real = se.payload_to_csv
    calls = {"n": 0}

    def flaky(payload):
        calls["n"] += 1
        if calls["n"] == 2:  # validation passes, generation fails
            raise RuntimeError("boom")
        return real(payload)

    monkeypatch.setattr(se, "payload_to_csv", flaky)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == before  # no charge, no operation
    assert _completed_charges(auth_env, user_id) == []
    assert _all_export_ops(auth_env, user_id) == []
    monkeypatch.setattr(se, "payload_to_csv", real)
    # Phase C: a failed generation does not gate anything — exports
    # are unconditionally unlocked, so the next format is free too.
    with auth_env.sessions() as db:
        assert C.is_export_unlocked(db, user_id, rid) is True
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert _balance(auth_env, user_id) == before
    csv_r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200
    assert _balance(auth_env, user_id) == before
    assert _all_export_ops(auth_env, user_id) == []
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_insufficient_credits_no_charge_no_unlock(auth_env):
    # Phase C re-base: the signup grant is removed, so this user has
    # a zero balance — the old "insufficient credits" case is now a
    # free success on every report and every format (no 402, no
    # balance consult, no operation/ledger).
    _, user_id, rid, csrf = _setup(auth_env, extra_credits=0)
    assert _balance(auth_env, user_id) == 0
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert _balance(auth_env, user_id) == 0
    rid2 = _create_result(auth_env, user_id, "second.log")
    for path in (f"/reports/{rid2}/exports/csv", f"/reports/{rid2}/pdf"):
        r = auth_env.client.post(path, data={"csrf_token": csrf})
        assert r.status_code == 200, (path, r.status_code, r.text[:200])
    assert _balance(auth_env, user_id) == 0
    assert _all_export_ops(auth_env, user_id) == []
    with auth_env.sessions() as db:
        assert C.is_export_unlocked(db, user_id, rid2) is True
        assert C.is_export_unlocked(db, user_id, rid) is True


def test_free_generation_failure_after_unlock_charges_nothing(auth_env, monkeypatch):
    _, user_id, rid, csrf = _setup(auth_env)
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    mid = _balance(auth_env, user_id)
    from app import structured_export as se

    def boom(payload, fmt):
        raise RuntimeError("gen boom")

    real_generate = se.generate_export
    monkeypatch.setattr(se, "generate_export", boom)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == mid
    # Restore manually: monkeypatch.undo() would also revert the
    # fixture's own patches (DB override, auth limiter).
    monkeypatch.setattr(se, "generate_export", real_generate)
    # Still unlocked afterwards: the retry is free.
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 200
    assert _balance(auth_env, user_id) == mid


# --- My Reports ---------------------------------------------------------------

def test_my_reports_row_actions_follow_unlock(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    # PREMISE CHANGED (2026-11-10 founder fidelity ruling, PR #177
    # S3-G1): the row's Export dropdown is removed — the Lovable
    # design uses direct controls. Each format is now its own direct
    # submit on the row; the unlock semantics below are unchanged.
    # Action row: Open / Export PDF / Export CSV / Export JSON /
    # Share / Extend — no dropdown trigger remains.
    assert f'href="/reports/{rid}"' in page.text
    assert f"/reports/{rid}/pdf" in page.text
    assert f"/reports/{rid}/exports/csv" in page.text
    assert f"/reports/{rid}/exports/json" in page.text
    # Phase C (Decision 5): the Extend control is removed from My
    # Reports — retention extensions are no longer sold.
    assert f"/reports/{rid}/retention" not in page.text
    assert ">Export</button>" not in page.text
    assert ">Export PDF</button>" in page.text
    assert ">Export CSV</button>" in page.text
    assert ">Export JSON</button>" in page.text
    assert ">Share</button>" in page.text
    assert ">Extend</button>" not in page.text
    assert "(2 credits)" not in page.text
    assert "data-confirm" in page.text  # popup before any charge
    # Phase C: the row's CSV export is free (no unlock charge), and
    # the row's PDF action is a direct free download as well.
    before = _balance(auth_env, user_id)
    csv_r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200
    assert _balance(auth_env, user_id) == before
    assert _all_export_ops(auth_env, user_id) == []
    page2 = auth_env.client.get("/reports")
    # Phase C (Decision 4 / C2): the per-format "export-unlocked"
    # confirm wording is RETIRED — every export form on the row
    # carries the single free confirm in both states, before and
    # after any export (the row never had a locked state to leave).
    assert page2.text.count(
        'data-confirm="Exports are free for this report."') >= 3
    assert "export-unlocked" not in page2.text
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before


# --- Report page UI contract ----------------------------------------------------

def test_report_page_two_buttons_no_microcopy_popups(auth_env):
    # PREMISE CHANGED (issue #136, one job per page): the #129
    # Export · Share button row (plus the #106 Analysis button) is
    # superseded by ONE "Actions" menu holding the same actions.
    # The no-microcopy / no-forms-on-page / popup contracts below
    # are unchanged from #129; only the container changed. The full
    # #136 contract lives in test_issue136_actions_menu.py.
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    # Exactly one Actions menu; the old top-level buttons are gone
    # and the menu items carry the Export format labels.
    # PREMISE CHANGED AGAIN (fidelity G1, 2026-11-10): the Actions
    # menu is retired — exports are direct controls (gold PDF +
    # CSV/JSON chips) carrying the same forms and labels.
    assert 'id="actions-btn"' not in page.text
    assert 'id="actions-menu"' not in page.text
    assert 'data-s1-actions' in page.text
    assert 'id="export-btn"' not in page.text
    assert ">Export PDF" in page.text
    assert ">Export CSV" in page.text
    assert ">Export JSON" in page.text
    assert "Export PDF (2 credits)" not in page.text
    # No explanatory microcopy / paragraphs for the actions.
    for gone in (
        "Charged 2 credits only when the PDF is first generated",
        "First generation is charged; re-download is free",
        "Sharing is free. Anyone holding the link",
        "Extending keeps this report longer",
        "This report is retained until",
    ):
        assert gone not in page.text, gone
    # Extend and share FORMS moved off the report page.
    assert f'action="/reports/{rid}/retention"' not in page.text
    assert f'action="/reports/{rid}/share"' not in page.text
    # Confirmation popup before any charge + in-page share popup with
    # a copyable link and an "Open in email" (mailto) action.
    assert "data-confirm" in page.text
    assert 'id="ss-confirm"' in page.text
    assert 'id="share-modal"' in page.text
    assert 'id="share-link"' in page.text
    assert 'id="share-mailto"' in page.text
    assert "Open in email" in page.text
    assert "mailto:" in page.text


# --- Sharing interaction (§5) ---------------------------------------------------

def test_share_pdf_accepts_export_unlocked_via_csv(paid_env):
    """PREMISE CHANGED (issue #135): the shared PDF is served by a
    pdf-FORMAT link at /s/<token> (not the /pdf subroute of a txt
    link). The #129 §5 rule carries over: export-unlocked via CSV
    counts as PDF purchased for sharing.

    PREMISE CHANGED AGAIN (issue #164 Phase C, C8): the share-create
    #135 unlock 402 gate is REMOVED — a pdf-format link can be
    created with no unlock at all, charges nothing, and the shared
    PDF is generated on the fly (no completed PDF operation exists).
    The txt link's /pdf subroute still serves nothing (404)."""
    from test_report_sharing import (
        _anon_client,
        _create_share,
        _make_report,
        _token_from,
    )
    from test_phase2b_paid_e2e import _signup_verify_login

    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    _grant(env, uid, 10)
    before = _balance(env, uid)
    resp = _create_share(env, rid, csrf)
    assert resp.status_code == 200, resp.text[:300]
    token = _token_from(resp)
    anon = _anon_client()
    # The txt link still serves no PDF at the old subroute.
    assert anon.get(f"/s/{token}/pdf").status_code == 404
    # No unlock gate: pdf-format creation succeeds immediately.
    created = env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": "s135-pdf-link",
              "format": "pdf"})
    assert created.status_code == 200, created.text[:300]
    pdf_token = _token_from(created)
    # A CSV export is also free now — no PDF is ever generated by
    # the owner and nothing is charged for either action.
    csv_r = env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200, csv_r.text[:300]
    assert _ops(env, uid, "pdf") == []
    assert _balance(env, uid) == before
    got = anon.get(f"/s/{pdf_token}")
    assert got.status_code == 200, got.status_code
    assert got.content[:4] == b"%PDF"
    assert "application/pdf" in got.headers.get("content-type", "")
