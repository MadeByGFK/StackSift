"""Issue #145: Share for Investigation Reports (share-only).

Founder ruling 2026-11-17: option (a) — an Investigation Report
(deep_dive Result) can be shared on the #135 model: link free,
TXT/PDF/JSON/CSV included with the purchase, links listed/revocable
in Settings -> Report Access, 90-day included retention (already the
store_product_result default — pinned here). No paid extension.

TEETH: on the pre-#145 tree every create below 404s at
_share_owner_gate (deep_dive not admitted) — verified by running this
file against the pre-change tree.
"""

import json
from datetime import timedelta

import pytest
from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from test_phase2b_paid_e2e import paid_env, _signup_verify_login  # noqa: F401
from test_report_sharing import _anon_client, _make_report, _token_from

from app import credits as C, models as M
from app import structured_export as SE


def _setup_deep_dive(env):
    """Owner + source analysis + a dollar-paid Investigation Report.

    The established fixture pattern (test_issue163_branding): seed the
    $9 entitlement for the source, then generate via the real route.
    Returns (uid, csrf, source_id, deep_dive_result_id).
    """
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    from product_seed import seed_entitlement_for_source
    seed_entitlement_for_source(env.sessions, rid)
    gen = env.client.post(f"/reports/{rid}/deep-dive",
                          data={"csrf_token": csrf})
    assert gen.status_code == 200, gen.text[:300]
    return uid, csrf, rid, gen.json()["analysis_result_id"]


def _create(env, rid, csrf, key, fmt=None):
    data = {"csrf_token": csrf, "idempotency_key": key}
    if fmt is not None:
        data["format"] = fmt
    return env.client.post(f"/reports/{rid}/share", data=data)


def _stored_payload(env, rid):
    with env.sessions() as db:
        result = db.get(M.Result, rid)
        return json.loads(result.storage_manifest)


def _sharing_rows(env, rid):
    with env.sessions() as db:
        return db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).all()


def _serve(token, fmt_path=""):
    anon = _anon_client()
    return anon.get(f"/s/{token}{fmt_path}")


# --- creation -----------------------------------------------------------------

def test_create_all_four_formats_free(paid_env):
    env = paid_env
    uid, csrf, _src, dd = _setup_deep_dive(env)
    for i, fmt in enumerate(("txt", "pdf", "json", "csv")):
        resp = _create(env, dd, csrf, f"145-create-{fmt}", fmt)
        assert resp.status_code == 200, (fmt, resp.text[:300])
        _token_from(resp)  # a well-formed /s/<token> URL
    rows = _sharing_rows(env, dd)
    assert sorted(r.share_format for r in rows) == ["csv", "json", "pdf", "txt"]
    # Creation charged nothing: no operations of any kind were created
    # for the share actions on this report.
    with env.sessions() as db:
        ops = db.query(M.Operation).filter(
            M.Operation.user_id == uid,
            M.Operation.type.in_(("pdf", "structured_export"))).count()
    assert ops == 0


def test_create_replay_same_key(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    first = _create(env, dd, csrf, "145-replay", "pdf")
    assert first.status_code == 200, first.text[:300]
    replay = _create(env, dd, csrf, "145-replay", "pdf")
    assert replay.status_code == 200, replay.text[:300]
    assert replay.json()["status"] == "already_shared"
    assert len(_sharing_rows(env, dd)) == 1


def test_create_same_key_different_format_conflicts(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    assert _create(env, dd, csrf, "145-key", "txt").status_code == 200
    conflict = _create(env, dd, csrf, "145-key", "csv")
    assert conflict.status_code == 409, conflict.text[:300]


def test_retention_is_ninety_days(paid_env):
    env = paid_env
    _uid, _csrf, _src, dd = _setup_deep_dive(env)
    with env.sessions() as db:
        result = db.get(M.Result, dd)
        delta = C._as_aware(result.expires_at) - C._as_aware(result.ready_at)
    assert delta == timedelta(days=90)


# --- serving ------------------------------------------------------------------

def test_serve_txt_is_public_projection_text(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    token = _token_from(_create(env, dd, csrf, "145-txt", "txt"))
    resp = _serve(token)
    assert resp.status_code == 200, resp.text[:300]
    assert resp.headers["content-type"].startswith("text/plain")
    payload = _stored_payload(env, dd)
    from app import deep_dive as DD
    projection = DD.public_projection(DD.validate_artifact(payload))
    assert projection["summary"] in resp.text
    assert "Investigation Report" in resp.text
    # The public projection only — no internal artifact fields cross.
    assert "report_kind" not in resp.text
    assert "integrity" not in resp.text


def test_serve_json_csv_match_owner_generators(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    payload = _stored_payload(env, dd)
    for fmt in ("json", "csv"):
        token = _token_from(_create(env, dd, csrf, f"145-{fmt}", fmt))
        resp = _serve(token)
        assert resp.status_code == 200, (fmt, resp.text[:300])
        assert resp.content == SE.generate_export(payload, fmt)


def test_serve_pdf(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    token = _token_from(_create(env, dd, csrf, "145-pdf", "pdf"))
    resp = _serve(token)
    assert resp.status_code == 200, resp.text[:300]
    assert resp.headers["content-type"].startswith("application/pdf")
    assert resp.content[:5] == b"%PDF-"


def test_link_serves_only_its_own_format(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    token = _token_from(_create(env, dd, csrf, "145-txtonly", "txt"))
    # The legacy /pdf subroute refuses a non-pdf link identically.
    resp = _serve(token, "/pdf")
    assert resp.status_code == 404, resp.text[:200]


def test_pdf_share_follows_branding_replay_policy(paid_env):
    """Codex P2 on PR #197: a branding row defeats stored-PDF replay
    on the owner's route — the share must follow the same policy, or
    it keeps serving the pre-branding PDF forever."""
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    own = env.client.post(f"/reports/{dd}/pdf", data={"csrf_token": csrf})
    assert own.status_code == 200 and own.content[:5] == b"%PDF-"
    token = _token_from(_create(env, dd, csrf, "145-brand", "pdf"))
    first = _serve(token)
    assert first.status_code == 200, first.text[:200]
    assert first.content == own.content  # stored replay (no branding row)
    r = env.client.post("/settings/branding", data={
        "csrf_token": csrf, "business_name": "Acme Consulting",
        "report_title": "", "client_name": "", "accent": ""})
    assert r.status_code in (200, 303), r.text[:300]
    second = _serve(token)
    assert second.status_code == 200, second.text[:200]
    assert second.content != first.content
    from test_issue162_brief import _pdf_text
    assert "Acme Consulting" in _pdf_text(second.content)


# --- the identical-unavailable family ------------------------------------------

def test_revoked_and_unknown_and_foreign(paid_env):
    env = paid_env
    uid, csrf, _src, dd = _setup_deep_dive(env)
    token = _token_from(_create(env, dd, csrf, "145-rev", "txt"))
    # Revoke via the row action (format-scoped).
    rev = env.client.post(
        f"/reports/{dd}/share/revoke",
        data={"csrf_token": csrf, "idempotency_key": "145-rev-1",
              "format": "txt"})
    assert rev.status_code == 200, rev.text[:300]
    revoked = _serve(token)
    unknown = _serve("0" * 64)
    assert revoked.status_code == unknown.status_code == 404
    assert revoked.text == unknown.text
    # Another user cannot create a share for this report at all.
    _email2, _uid2, csrf2 = _signup_verify_login(env)
    foreign = _create(env, dd, csrf2, "145-foreign", "txt")
    assert foreign.status_code == 404, foreign.text[:300]


def test_expired_report_create_410_and_link_dies(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    token = _token_from(_create(env, dd, csrf, "145-exp", "txt"))
    assert _serve(token).status_code == 200
    with env.sessions() as db:
        result = db.get(M.Result, dd)
        result.expires_at = C._utcnow() - timedelta(minutes=1)
        db.commit()
    assert _serve(token).status_code == 404
    late = _create(env, dd, csrf, "145-exp-late", "csv")
    assert late.status_code == 410, late.text[:300]


def test_comparison_still_rejected(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid, result_type="comparison")
    resp = _create(env, rid, csrf, "145-cmp", "txt")
    assert resp.status_code == 422, resp.text[:300]


# --- Settings -> Report Access (cross-surface, API level) ----------------------

def test_settings_lists_and_revokes(paid_env):
    env = paid_env
    _uid, csrf, _src, dd = _setup_deep_dive(env)
    token = _token_from(_create(env, dd, csrf, "145-set", "json"))
    rows = _sharing_rows(env, dd)
    assert len(rows) == 1
    page = env.client.get("/settings")
    assert page.status_code == 200, page.text[:300]
    assert "json" in page.text and str(rows[0].id) in page.text
    rev = env.client.post(
        f"/settings/report-access/{rows[0].id}/revoke",
        data={"csrf_token": csrf})
    assert rev.status_code in (200, 303), rev.text[:300]
    assert _serve(token).status_code == 404
