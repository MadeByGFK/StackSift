"""Issue #106 Stage 2: paid Analysis Report — charging/generation core.

Founder rulings (2026-11-03): price 3 credits, charged on SUCCESS only
(0 on failure); user-facing name "Analysis Report", label "Analysis",
placed after Export; legacy reports (no retained evidence) are NOT
eligible — 422 with the ruled re-analyze message, no charge, no
retroactive repair.

Cross-feature interaction cases (spec shift-left, founder ruling
2026-11-03) live here and in test_deep_dive_exports.py:
export x analysis, share x analysis, retention/expiry x analysis,
charge-key replay, failure-path 0 charge, legacy rejection, and
comparison/batch/analysis-of-analysis rejection before reservation.

These tests must FAIL on the pre-Stage-2 tree (423c105a: no route, no
COST_DEEP_DIVE, no deep_dive module) and PASS on the built tree.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import (
    _balance,
    _drain_signup,
    _grant,
    _ops,
    _session_csrf,
    _setup,
)
from test_phase2b_reports_pdf import _login, _signup_and_verify
from app import credits as C
from app import deep_dive as dd


def _analysis_ops(auth_env, user_id):
    return _ops(auth_env, user_id, "deep_dive")


def _custom_result(auth_env, user_id, payload, *, expired=False,
                   report_type="analysis"):
    from app import models
    manifest = json.dumps(payload, default=str)
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        result = models.Result(
            user_id=user_id, type=report_type,
            free_request_id=f"test-{uuid.uuid4().hex}",
            storage_manifest=manifest,
            integrity_digest=hashlib.sha256(manifest.encode()).hexdigest(),
            byte_count=len(manifest.encode()),
            ready_at=now - timedelta(days=8) if expired else now,
            expires_at=now - timedelta(days=1) if expired
            else now + timedelta(days=7),
        )
        db.add(result)
        db.commit()
        return result.id
    finally:
        db.close()


def _eligible_payload():
    from app.service import analyze_upload
    log = (
        b"2024-01-01 10:00:00 ERROR DatabaseError: connection to db-01 refused\n"
        b"2024-01-01 10:00:01 ERROR DatabaseError: connection to db-01 refused\n"
        b"2024-01-01 10:00:02 WARN Connection pool exhausted\n"
    )
    data = analyze_upload("eligible.log", log)
    assert "error" not in data, data
    return data


def _generate(auth_env, rid, csrf):
    # PREMISE CHANGED (#164 Phase A, A10: dollar-product): NEW
    # Analysis Report generation is dollar-only. Fixtures seed a
    # completed $9 product purchase + available entitlement for the
    # source owner, and the POST redeems it — no credits move.
    from product_seed import seed_entitlement_for_source
    seed_entitlement_for_source(auth_env.sessions, rid)
    return auth_env.client.post(
        f"/reports/{rid}/deep-dive", data={"csrf_token": csrf})


def _generate_raw(auth_env, rid, csrf):
    """POST deep-dive WITHOUT seeding an entitlement (402 premise)."""
    return auth_env.client.post(
        f"/reports/{rid}/deep-dive", data={"csrf_token": csrf})


def _redemptions(auth_env, user_id):
    from app import models
    db = auth_env.sessions()
    try:
        return db.query(models.EntitlementRedemption).join(
            models.Entitlement,
            models.Entitlement.id == models.EntitlementRedemption.entitlement_id,
        ).filter(models.Entitlement.user_id == user_id).all()
    finally:
        db.close()


# --- charging core -----------------------------------------------------------

def test_analysis_success_charges_3_once_and_creates_report(auth_env):
    # PREMISE CHANGED (#164 Phase A, A10: dollar-product): the
    # 3-credit charge is retired for NEW purchases. Success now
    # redeems the $9 entitlement exactly once: price_cents == 900,
    # credit balance and credit Operations untouched, artifact is a
    # distinct deep_dive Result with a 90-day life (Phase A terms).
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["status"] == "completed"
    assert body["price_cents"] == 900
    assert _balance(auth_env, user_id) == before  # no credit movement
    assert _analysis_ops(auth_env, user_id) == []  # no credit Operation
    reds = _redemptions(auth_env, user_id)
    assert len(reds) == 1 and reds[0].status == "completed"
    from app import models
    db = auth_env.sessions()
    try:
        artifact = db.get(models.Result, uuid.UUID(body["analysis_result_id"]))
        assert artifact is not None and artifact.type == "deep_dive"
        assert artifact.product_redemption_id == reds[0].id
        manifest = json.loads(artifact.storage_manifest)
        assert manifest["report_kind"] == "deep_dive"
        assert manifest["source_result_id"] == str(rid)
        assert (C._as_aware(artifact.expires_at)
                - C._as_aware(artifact.ready_at)).days == 90
        ent = db.query(models.Entitlement).filter(
            models.Entitlement.user_id == user_id).one()
        assert ent.status == "redeemed"
    finally:
        db.close()
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_analysis_replay_same_identity_free_returns_same_artifact(auth_env):
    # PREMISE CHANGED (#164): replay is still free and returns the
    # same artifact — now it also consumes no second entitlement.
    _, user_id, rid, csrf = _setup(auth_env)
    first = _generate(auth_env, rid, csrf)
    assert first.status_code == 200
    before = _balance(auth_env, user_id)
    for _ in range(2):
        again = _generate(auth_env, rid, csrf)
        assert again.status_code == 200
        assert again.json()["analysis_result_id"] == \
            first.json()["analysis_result_id"]
        assert again.json()["replayed"] is True
    assert _balance(auth_env, user_id) == before  # replay never re-charges
    assert _analysis_ops(auth_env, user_id) == []
    reds = _redemptions(auth_env, user_id)
    assert len([r for r in reds if r.status == "completed"]) == 1


def test_analysis_invalid_csrf_403_no_charge(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    r = auth_env.client.post(
        f"/reports/{rid}/deep-dive", data={"csrf_token": "wrong"})
    assert r.status_code == 403
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []


def test_analysis_insufficient_credits_402_no_operation(auth_env):
    # PREMISE CHANGED (#164 Phase A, A10: dollar-product): credits no
    # longer buy an Analysis Report at ANY balance. With no $9
    # entitlement held, generation is a 402 directing to the product
    # checkout — even with a positive credit balance — and creates no
    # credit Operation and no redemption.
    _, user_id, rid, csrf = _setup(auth_env, extra_credits=0)
    assert _generate(auth_env, rid, csrf).status_code == 200
    payload = _eligible_payload()
    rid2 = _custom_result(auth_env, user_id, payload)
    csrf2 = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    assert before > 0  # credits exist; they simply do not apply here
    r = _generate_raw(auth_env, rid2, csrf2)
    assert r.status_code == 402, r.text[:300]
    assert r.json()["purchase_url"] == f"/reports/{rid2}/investigation-checkout"
    assert r.json()["checkout_url"] == f"/reports/{rid2}/investigation-checkout"
    assert r.json()["price_cents"] == 900
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []  # no credit reservation
    assert len(_redemptions(auth_env, user_id)) == 1  # only report 1's


def test_analysis_failure_charges_zero_then_retry_succeeds_once(auth_env, monkeypatch):
    # PREMISE CHANGED (#164 / F2): a generation failure NEVER consumes
    # the purchase — the entitlement is released back to available
    # (redemption row 'released', no credit movement anywhere), and
    # the retry succeeds on that same entitlement, exactly once.
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    real = dd.build_deep_dive
    monkeypatch.setattr(dd, "build_deep_dive",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []
    reds = _redemptions(auth_env, user_id)
    assert len(reds) == 1 and reds[0].status == "released"
    monkeypatch.setattr(dd, "build_deep_dive", real)
    retry = _generate(auth_env, rid, csrf)
    assert retry.status_code == 200, retry.text[:300]
    assert _balance(auth_env, user_id) == before  # dollars, not credits
    reds = _redemptions(auth_env, user_id)
    assert sorted(x.status for x in reds) == ["completed", "released"]
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_analysis_reserved_in_progress_409(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    from app import models
    db = auth_env.sessions()
    try:
        db.add(models.Operation(
            user_id=user_id, type="deep_dive",
            idempotency_key=f"analysis-{rid}-v1",
            request_hash="0" * 64, cost=3, pricing_version=1,
            status="reserved", worker_id="other-worker",
            lease_generation=1,
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ))
        db.commit()
    finally:
        db.close()
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 409
    assert _balance(auth_env, user_id) == before


# --- eligibility gates (all before reservation, 0 charge) --------------------

def test_analysis_legacy_report_422_ruled_message_no_charge(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    payload = {
        "filename": "legacy.log",
        "results": {
            "total_lines": 2, "parsed_lines": 2, "malformed_lines": 0,
            "level_counts": {"ERROR": 2},
            "issues": {"DatabaseError: connection failed": {
                "level": "ERROR", "count": 2, "services": ["db"],
                "first_seen": None, "last_seen": None}},
            # No diagnostic_evidence: created before evidence capture.
        },
        "sorted_issues": [],
    }
    rid = _custom_result(auth_env, user_id, payload)
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 422, r.text[:300]
    assert "does not retain enough evidence" in r.json()["error"]
    assert "Analyze the original log again" in r.json()["error"]
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []


def test_analysis_expired_source_410_no_charge(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    rid = _custom_result(auth_env, user_id, _eligible_payload(), expired=True)
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    # No entitlement held for this source: the expired-source 410
    # gate stands (the F5 within-window redemption case, where an
    # entitlement IS held, is covered by the Phase A suite).
    r = _generate_raw(auth_env, rid, csrf)
    assert r.status_code == 410
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []


def test_analysis_foreign_source_404(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    email2, user2 = _signup_and_verify(auth_env)
    _login(auth_env, email2)
    csrf2 = _session_csrf(auth_env)
    r = _generate(auth_env, rid, csrf2)
    assert r.status_code == 404
    assert _analysis_ops(auth_env, user2) == []


def test_analysis_of_comparison_rejected_422_before_reservation(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    payload = _eligible_payload()
    payload["report_kind"] = "comparison"
    rid = _custom_result(auth_env, user_id, payload, report_type="comparison")
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 422
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []


def test_analysis_of_batch_rejected_422_before_reservation(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    payload = _eligible_payload()
    payload["report_kind"] = "batch"
    rid = _custom_result(auth_env, user_id, payload)
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 422
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []


def test_analysis_of_analysis_report_rejected_422(auth_env):
    # PREMISE CHANGED (#164): still rejected 422 before any money
    # movement — now measured on redemptions, not credit Operations.
    _, user_id, rid, csrf = _setup(auth_env)
    first = _generate(auth_env, rid, csrf)
    assert first.status_code == 200
    analysis_id = first.json()["analysis_result_id"]
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, analysis_id, csrf)
    assert r.status_code == 422
    assert _balance(auth_env, user_id) == before
    assert len(_redemptions(auth_env, user_id)) == 1  # no new redemption
    assert _analysis_ops(auth_env, user_id) == []


def test_analysis_too_many_groups_422_no_charge(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    issues = {}
    metadata = {}
    for i in range(dd.MAX_GROUPS + 1):
        template = f"Distinct failure variant {i} happened"
        issues[template] = {"level": "ERROR", "count": 1, "services": ["db"],
                            "first_seen": None, "last_seen": None}
        metadata[template] = {"level_counts": {"ERROR": 1},
                              "peak_level": "ERROR"}
    payload = {
        "filename": "many.log",
        "results": {
            "total_lines": len(issues), "parsed_lines": len(issues),
            "malformed_lines": 0, "level_counts": {"ERROR": len(issues)},
            "issues": issues,
            "diagnostic_evidence": {
                "schema_version": 1, "grouping_version": "106-stage1-v1",
                "coordinate": "analysis line", "groups": {},
                "severity_metadata": metadata,
                "groups_truncated": False, "truncated": False,
            },
        },
        "sorted_issues": [],
    }
    rid = _custom_result(auth_env, user_id, payload)
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 422
    assert _balance(auth_env, user_id) == before
    assert _analysis_ops(auth_env, user_id) == []


# --- view + content contract ---------------------------------------------------

def test_analysis_view_renders_without_internal_labels(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    first = _generate(auth_env, rid, csrf)
    analysis_id = first.json()["analysis_result_id"]
    page = auth_env.client.get(f"/reports/{analysis_id}")
    assert page.status_code == 200, page.text[:300]
    assert "Analysis Report" in page.text
    for forbidden in ("_evidence_refs", "evidence_refs",
                      "source_integrity_digest", "generator_version"):
        assert forbidden not in page.text


def test_report_page_analysis_action_after_export(auth_env, monkeypatch):
    # PREMISE CHANGED (issue #136, one job per page): the Export ·
    # Analysis · Share button row collapsed into ONE "Actions" menu.
    # The placement rule survives inside the menu: the Export items
    # come first, then Analysis, then Share.
    # #164: the dollar copy renders when the product Price is
    # configured (this fixture env does not set it by default).
    monkeypatch.setenv("STRIPE_PRICE_INVESTIGATION_REPORT",
                       "price_test_investigation")
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    assert page.text.count('id="actions-btn"') == 1
    assert 'id="export-btn"' not in page.text
    export_at = page.text.index(f'action="/reports/{rid}/pdf"')
    analysis_at = page.text.index('id="analysis-btn"')
    share_at = page.text.index('id="share-btn"')
    assert export_at < analysis_at < share_at
    # PREMISE CHANGED (#164): dollar copy replaces the credit copy;
    # the legacy "charged only if generation succeeds" phrase must
    # NOT appear on the dollar path (A6(3) — payment is captured at
    # checkout; a failure simply never consumes the purchase).
    assert "Investigation Report costs $9" in page.text
    assert "Payment is captured at checkout" in page.text
    assert "Analysis Report costs 3 credits" not in page.text
    assert "charged only if generation succeeds" not in page.text


def test_reports_list_row_has_analysis_action(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    assert "analysis-open" in page.text


def test_reports_list_deep_dive_row_has_no_extend_but_normal_row_does(auth_env):
    # The retention route only admits analysis/comparison sources, so
    # an Extend action on an Analysis Report (deep_dive) row is a dead
    # button (its POST 404s). It must not be rendered for that row,
    # while a normal report row keeps Extend unchanged.
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    analysis_id = gen.json()["analysis_result_id"]
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    cards = page.text.split('<tr class="card s3-row">')

    def _card_for(report_id):
        # Match the row's own View link (not e.g. a source row's
        # Analysis link, which also points at the derived report).
        view_link = f'href="/reports/{report_id}" class="btn btn-ghost">View'
        matches = [c for c in cards if view_link in c]
        assert len(matches) == 1, report_id
        return matches[0]

    normal_card = _card_for(str(rid))
    assert "Extend" in normal_card
    assert f"/reports/{rid}/retention" in normal_card
    deep_dive_card = _card_for(analysis_id)
    assert "Extend" not in deep_dive_card
    assert f"/reports/{analysis_id}/retention" not in deep_dive_card


# --- cross-feature interactions ------------------------------------------------

def test_export_times_analysis_charges_are_independent(auth_env):
    # PREMISE CHANGED (#164 Phase A): the independence survives with
    # new terms — the SOURCE export unlock is still its own 2-credit
    # charge and does not pay for the Analysis Report; the Analysis
    # Report is bought with the $9 entitlement (no credits), and ITS
    # exports are included free (they never hit the credit unlock).
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert _balance(auth_env, user_id) == before - 2
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200
    assert _balance(auth_env, user_id) == before - 2  # dollar, not credits
    analysis_id = gen.json()["analysis_result_id"]
    apdf = auth_env.client.post(
        f"/reports/{analysis_id}/pdf", data={"csrf_token": csrf})
    assert apdf.status_code == 200 and apdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before - 2  # exports included
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_share_times_analysis_share_stays_free_and_separate(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    share = auth_env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert share.status_code == 200, share.text[:300]
    assert _balance(auth_env, user_id) == before  # sharing is free
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200
    # PREMISE CHANGED (#164): generation is the $9 entitlement —
    # the credit balance is untouched by it.
    assert _balance(auth_env, user_id) == before
    # The Analysis Report itself is not shareable through the
    # single-file share path (fails closed, still no charge).
    analysis_id = gen.json()["analysis_result_id"]
    share2 = auth_env.client.post(
        f"/reports/{analysis_id}/share",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert share2.status_code in (404, 422)
    assert _balance(auth_env, user_id) == before


def test_retention_times_analysis_source_extension_leaves_artifact(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200
    analysis_id = uuid.UUID(gen.json()["analysis_result_id"])
    from app import models
    db = auth_env.sessions()
    try:
        artifact_expiry = db.get(models.Result, analysis_id).expires_at
        source_expiry = db.get(models.Result, rid).expires_at
    finally:
        db.close()
    before = _balance(auth_env, user_id)
    ext = auth_env.client.post(
        f"/reports/{rid}/retention",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert ext.status_code == 200, ext.text[:300]
    assert _balance(auth_env, user_id) == before - 1  # retention's own price
    db = auth_env.sessions()
    try:
        # Source extended +90 days; the Analysis artifact's own
        # retention is untouched (independent life — 90 days under
        # the #164 dollar terms, formerly 7 on the credit path).
        assert db.get(models.Result, rid).expires_at > source_expiry
        assert db.get(models.Result, analysis_id).expires_at == artifact_expiry
    finally:
        db.close()


# --- generator content rules (unit) ---------------------------------------------

def test_generator_abstains_when_no_rule_is_supported():
    payload = _eligible_payload()
    # Replace issues/evidence with an unmatched template.
    from app.service import analyze_upload
    data = analyze_upload(
        "odd.log",
        b"2024-01-01 10:00:00 ERROR Frobnicate wobble detected in module seven\n"
        b"2024-01-01 10:00:01 ERROR Frobnicate wobble detected in module seven\n")
    artifact = dd.build_deep_dive(data)
    causes = artifact["groups"][0]["possible_causes"]
    assert [c["text"] for c in causes] == [dd.ABSTENTION]


def test_generator_refused_cause_is_bounded_and_grounded():
    artifact = dd.build_deep_dive(_eligible_payload())
    blob = json.dumps(artifact)
    assert "caused by" not in blob
    assert "crashed" not in blob
    refused = next(g for g in artifact["groups"] if "refused" in g["template"])
    assert "does not establish why" in refused["possible_causes"][0]["text"]
    # Every claim carries machine-checkable evidence references.
    for group in artifact["groups"]:
        for key in ("observations", "explanations", "possible_causes",
                    "first_checks"):
            for claim in group[key]:
                assert claim["evidence_refs"], (group["template"], key)


def test_public_projection_has_no_internal_labels_or_scores():
    artifact = dd.build_deep_dive(_eligible_payload())
    projection = dd.public_projection(artifact)
    blob = json.dumps(projection)
    for forbidden in ("evidence_refs", "source_integrity_digest",
                      "generator_version", "signal", "tier", "score"):
        assert forbidden not in blob
    excerpt_texts = [e["text"] for g in projection["groups"]
                     for e in g["excerpts"]]
    assert any("refused" in t for t in excerpt_texts)
