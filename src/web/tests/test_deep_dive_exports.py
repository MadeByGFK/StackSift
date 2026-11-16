"""Issue #106 Stage 2: Analysis Report export integration (#129).

The generated Analysis Report is a distinct report identity for the
#129 per-report export unlock: its first successful format generation
(PDF/CSV/JSON) charges the single 2-credit unlock for THAT report,
every later format is free, and there is no separate Analysis PDF
price. CSV/JSON serve the artifact's public projection only — no
internal evidence refs, digests or generator internals in a download.
"""

import json

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import _balance, _ops, _setup
from app import credits as C


def _generate_analysis(auth_env, rid, csrf):
    # PREMISE CHANGED (#164 Phase A, A10: dollar-product): generation
    # redeems a seeded $9 entitlement; the artifact's exports are
    # then INCLUDED (free), superseding the 2-credit unlock premise
    # this module was written against for credit-era artifacts.
    from product_seed import seed_entitlement_for_source
    seed_entitlement_for_source(auth_env.sessions, rid)
    r = auth_env.client.post(
        f"/reports/{rid}/deep-dive", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    return r.json()["analysis_result_id"]


def test_analysis_pdf_first_unlocks_csv_and_json(auth_env):
    # PREMISE CHANGED (#164): for a dollar-paid report every format
    # is included in the $9 price — first PDF, then CSV and JSON all
    # succeed with ZERO credit movement (no 2-credit unlock exists
    # on this path anymore).
    _, user_id, rid, csrf = _setup(auth_env)
    analysis_id = _generate_analysis(auth_env, rid, csrf)
    before = _balance(auth_env, user_id)
    pdf = auth_env.client.post(
        f"/reports/{analysis_id}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before
    csv_r = auth_env.client.post(
        f"/reports/{analysis_id}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200, csv_r.text[:300]
    json_r = auth_env.client.post(
        f"/reports/{analysis_id}/exports/json", data={"csrf_token": csrf})
    assert json_r.status_code == 200, json_r.text[:300]
    assert _balance(auth_env, user_id) == before  # all formats included
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_analysis_csv_first_unlocks_pdf(auth_env):
    # PREMISE CHANGED (#164): CSV first, PDF second — both free for
    # a dollar-paid report, in either order.
    _, user_id, rid, csrf = _setup(auth_env)
    analysis_id = _generate_analysis(auth_env, rid, csrf)
    before = _balance(auth_env, user_id)
    csv_r = auth_env.client.post(
        f"/reports/{analysis_id}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200
    assert _balance(auth_env, user_id) == before
    pdf = auth_env.client.post(
        f"/reports/{analysis_id}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before


def test_analysis_csv_projection_shape(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    analysis_id = _generate_analysis(auth_env, rid, csrf)
    csv_r = auth_env.client.post(
        f"/reports/{analysis_id}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200
    text = csv_r.content.decode("utf-8")
    assert text.startswith("template,level,count,services,first_seen,last_seen")
    assert "failed to connect to db" in text


def test_analysis_json_projection_has_no_internals(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    analysis_id = _generate_analysis(auth_env, rid, csrf)
    json_r = auth_env.client.post(
        f"/reports/{analysis_id}/exports/json", data={"csrf_token": csrf})
    assert json_r.status_code == 200
    body = json.loads(json_r.content)
    assert body["display_name"] == "Analysis Report"
    blob = json_r.content.decode("utf-8")
    for forbidden in ("evidence_refs", "_evidence_refs",
                      "source_integrity_digest", "generator_version",
                      "integrity_digest"):
        assert forbidden not in blob
    assert body["groups"], "projection must carry the explained groups"
    assert any("failed to connect to db" in (e["text"] or "")
               for g in body["groups"] for e in g["excerpts"])
