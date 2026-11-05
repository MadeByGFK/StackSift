"""PR #132 remediation: the six Codex P2 findings on issue #129.

F5 (paid path, behavioral): PDF operation keys are canonicalized at
creation and unlock discovery tolerates existing noncanonical keys —
a first PDF export through an uppercase/unhyphenated URL charges the
single 2-credit unlock exactly once, a stored noncanonical completed
operation unlocks later formats for free, and a stored noncanonical
reserved operation fences a cross-format request (409, no charge).

F4 (behavioral): a batch row on My Reports (type "analysis",
report_kind "batch") offers PDF only — CSV/JSON are hidden, mirroring
the report page, because the structured route 422s batch reports.

F1/F2/F3/F6 (JS, assertion-level): there is no JS runtime harness for
these templates in this repo (browser tests are opt-in Playwright),
so these tests assert the fixed behavior contract in the RENDERED
pages — fresh idempotency keys after successful share actions
(crypto.randomUUID), HTTP-status-checked revoke, absolute share URLs
resolved against window.location.origin, and share responses bound
to the originating row button. Each assertion names a pattern that
does not exist on the pre-fix templates.
"""

import re
import uuid
from datetime import datetime, timedelta, timezone

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import (
    _balance,
    _custom_result,
    _ops,
    _sample_payload,
    _setup,
)
from test_issue129_export_unlock import _completed_charges
from test_phase2b_reports_pdf import _login, _signup_and_verify
from test_report_sharing import _anon_client
from app import credits as C, models as M, report_access as RA


def _insert_export_op(auth_env, user_id, op_type, key, status):
    from app import models
    db = auth_env.sessions()
    try:
        op = models.Operation(
            user_id=user_id, type=op_type, idempotency_key=key,
            request_hash="a" * 64, cost=2, worker_id="test-worker",
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            status=status,
        )
        db.add(op)
        db.commit()
        return op.id
    finally:
        db.close()


# --- F5: canonical PDF keys at creation --------------------------------------

def test_pdf_first_via_uppercase_url_then_csv_charges_once(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    pdf = auth_env.client.post(
        f"/reports/{str(rid).upper()}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before - 2
    # The stored operation key is the canonical form, not the raw
    # uppercase URL segment.
    pdf_ops = _ops(auth_env, user_id, "pdf")
    assert [op.idempotency_key for op in pdf_ops] == [f"pdf-{rid}"]
    csv_r = auth_env.client.post(
        f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200, csv_r.text[:300]
    # Exactly ONE 2-credit unlock charge total.
    assert _balance(auth_env, user_id) == before - 2
    assert len(_completed_charges(auth_env, user_id)) == 1


def test_pdf_first_via_unhyphenated_url_then_json_charges_once(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    pdf = auth_env.client.post(
        f"/reports/{rid.hex}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before - 2
    pdf_ops = _ops(auth_env, user_id, "pdf")
    assert [op.idempotency_key for op in pdf_ops] == [f"pdf-{rid}"]
    json_r = auth_env.client.post(
        f"/reports/{rid}/exports/json", data={"csrf_token": csrf})
    assert json_r.status_code == 200, json_r.text[:300]
    assert _balance(auth_env, user_id) == before - 2
    assert len(_completed_charges(auth_env, user_id)) == 1


# --- F5: discovery tolerates existing noncanonical keys ----------------------

def test_discovery_recognizes_noncanonical_completed_pdf_op(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    _insert_export_op(auth_env, user_id, "pdf", f"pdf-{rid.hex}", "completed")
    _insert_export_op(
        auth_env, user_id, "structured_export",
        f"structured-{str(rid).upper()}-csv-v1", "completed")
    with auth_env.sessions() as db:
        unlocked, in_progress = C.export_unlock_state(db, user_id, rid)
        assert unlocked is True
        assert in_progress is False
        assert C.is_export_unlocked(db, user_id, rid) is True


def test_completed_noncanonical_pdf_op_unlocks_csv_for_free(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    # A legacy completed PDF operation whose key carries the raw
    # uppercase URL segment (pre-canonicalization storage).
    _insert_export_op(
        auth_env, user_id, "pdf", f"pdf-{str(rid).upper()}", "completed")
    before = _balance(auth_env, user_id)
    csv_r = auth_env.client.post(
        f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200, csv_r.text[:300]
    # No second charge: the noncanonical completed op IS the unlock.
    assert _balance(auth_env, user_id) == before


def test_reserved_noncanonical_pdf_op_fences_csv(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    _insert_export_op(auth_env, user_id, "pdf", f"pdf-{rid.hex}", "reserved")
    with auth_env.sessions() as db:
        unlocked, in_progress = C.export_unlock_state(db, user_id, rid)
        assert unlocked is False
        assert in_progress is True
    before = _balance(auth_env, user_id)
    csv_r = auth_env.client.post(
        f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    # The cross-format fence holds: 409, and no second charge.
    assert csv_r.status_code == 409, csv_r.text[:300]
    assert _balance(auth_env, user_id) == before


def test_export_key_belongs_to_canonical_and_noncanonical():
    rid = uuid.uuid4()
    assert C.export_key_belongs_to(f"pdf-{rid}", rid)
    assert C.export_key_belongs_to(f"pdf-{rid}-retry-ab12cd34", rid)
    assert C.export_key_belongs_to(f"pdf-{str(rid).upper()}", rid)
    assert C.export_key_belongs_to(f"pdf-{rid.hex}", rid)
    assert C.export_key_belongs_to(f"pdf-{rid.hex}-retry-ab12cd34", rid)
    assert C.export_key_belongs_to(f"structured-{rid}-csv-v1", rid)
    assert C.export_key_belongs_to(f"structured-{str(rid).upper()}-json-v1", rid)
    assert C.export_key_belongs_to(f"structured-{rid.hex}-csv-v1", rid)
    other = uuid.uuid4()
    assert not C.export_key_belongs_to(f"pdf-{other}", rid)
    assert not C.export_key_belongs_to(f"pdf-{other.hex}", rid)
    assert not C.export_key_belongs_to(f"structured-{other}-csv-v1", rid)
    assert not C.export_key_belongs_to("unrelated-key", rid)


# --- F4: batch rows hide CSV/JSON ---------------------------------------------

def test_batch_row_hides_structured_exports(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    rid = _custom_result(
        auth_env, user_id, _sample_payload(report_kind="batch"))
    _login(auth_env, email)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    # PDF stays (the structured route is the one that 422s batch).
    assert f"/reports/{rid}/pdf" in page.text
    assert f"/reports/{rid}/exports/csv" not in page.text
    assert f"/reports/{rid}/exports/json" not in page.text


def test_single_file_row_still_offers_structured_exports(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    assert f"/reports/{rid}/exports/csv" in page.text
    assert f"/reports/{rid}/exports/json" in page.text


# --- F1/F2/F3: report page share script (assertion-level) ---------------------

def test_report_page_share_script_contracts(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    text = page.text
    # F1: fresh idempotency keys after each successful share action.
    assert "crypto.randomUUID()" in text
    assert "shareCreateKey = freshShareKey()" in text
    assert "shareRotateKey = freshShareKey()" in text
    assert "shareRevokeKey = freshShareKey()" in text
    # F2: revoke is reported only on HTTP success + revoked status.
    assert "d._httpOk && d.status === 'revoked'" in text
    assert "_httpStatus" in text
    # F3: share URLs are resolved to absolute before copy/mailto.
    assert "new URL(url, window.location.origin).href" in text


# --- F1/F2/F3/F6: My Reports share script (assertion-level) -------------------

def test_reports_page_share_script_contracts(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    text = page.text
    # F1: fresh keys are written back onto the originating row button.
    assert "crypto.randomUUID()" in text
    assert "originBtn.setAttribute('data-create-key', freshShareKey())" in text
    assert "originBtn.setAttribute('data-rotate-key', freshShareKey())" in text
    assert "originBtn.setAttribute('data-revoke-key', freshShareKey())" in text
    # F2: revoke is reported only on HTTP success + revoked status.
    assert "d._httpOk && d.status === 'revoked'" in text
    assert "_httpStatus" in text
    # F3: share URLs are resolved to absolute before copy/mailto.
    assert "new URL(url, window.location.origin).href" in text
    # F6: responses are bound to the originating report's button and
    # the shared popup DOM is not written after a row switch.
    assert "var originBtn = current;" in text
    assert "if (current !== originBtn) { return; }" in text


# --- PR #132 follow-up round ---------------------------------------------
# Finding 1 (P1, JS contract): the PDF fetch must fire ONLY after the
# confirmation popup's Continue — the confirm listener (registered
# before auth_form_script.html's PDF listener in both pages) stops
# immediate propagation for unconfirmed forms, Continue re-dispatches
# via requestSubmit(), and the confirmed flag is cleared on the
# confirmed pass so a later export asks again. No JS runtime harness
# exists in this repo, so these are rendered-page contract tests.
# Finding 2 (P2, JS contract): share controls reflect create/revoke
# success immediately, without a reload.
# Finding 3 (P2, behavioral): has_pdf_export_operation /
# find_shareable_pdf match legacy noncanonical PDF keys via
# credits.export_key_belongs_to, so an expired legacy PDF keeps the
# identical-404 share outcome instead of regenerating on the fly.


def _rewrite_pdf_op_key(env, user_id, new_key):
    with env.sessions() as db:
        op = db.query(M.Operation).filter(
            M.Operation.user_id == user_id,
            M.Operation.type == "pdf").one()
        op.idempotency_key = new_key
        db.commit()


# --- Follow-up F3: legacy PDF keys in report_access --------------------------

def test_has_pdf_export_operation_recognizes_uppercase_key(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    _insert_export_op(
        auth_env, user_id, "pdf", f"pdf-{str(rid).upper()}", "completed")
    with auth_env.sessions() as db:
        source = db.get(M.Result, rid)
        assert RA.has_pdf_export_operation(db, source) is True


def test_has_pdf_export_operation_recognizes_unhyphenated_retry_key(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    _insert_export_op(
        auth_env, user_id, "pdf",
        f"pdf-{rid.hex}-retry-ab12cd34", "completed")
    with auth_env.sessions() as db:
        source = db.get(M.Result, rid)
        assert RA.has_pdf_export_operation(db, source) is True


def test_find_shareable_pdf_recognizes_uppercase_key(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    pdf = auth_env.client.post(
        f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    _rewrite_pdf_op_key(auth_env, user_id, f"pdf-{str(rid).upper()}")
    with auth_env.sessions() as db:
        source = db.get(M.Result, rid)
        found = RA.find_shareable_pdf(db, source)
        assert found is not None
        pdf_result, pdf_bytes = found
        assert pdf_result.type == "pdf"
        assert pdf_bytes[:4] == b"%PDF"


def test_find_shareable_pdf_recognizes_unhyphenated_key(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    pdf = auth_env.client.post(
        f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    _rewrite_pdf_op_key(auth_env, user_id, f"pdf-{rid.hex}")
    with auth_env.sessions() as db:
        source = db.get(M.Result, rid)
        found = RA.find_shareable_pdf(db, source)
        assert found is not None
        pdf_result, pdf_bytes = found
        assert pdf_result.type == "pdf"
        assert pdf_bytes[:4] == b"%PDF"


def _create_share_token(auth_env, rid, csrf, key="followup-share-1"):
    resp = auth_env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": key})
    assert resp.status_code == 200, resp.text[:400]
    m = re.search(r"([0-9a-f]{64})", resp.json()["share_url"])
    assert m, resp.json()
    return m.group(1)


def test_shared_pdf_expired_legacy_uppercase_key_returns_identical_404(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    anon = _anon_client()
    pdf = auth_env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    # Issue #135: the PDF is shared through a pdf-FORMAT link (the
    # export above unlocked the report, so creation is allowed).
    resp = auth_env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": "followup-pdf-share-1",
              "format": "pdf"})
    assert resp.status_code == 200, resp.text[:400]
    import re as _re
    token = _re.search(r"([0-9a-f]{64})", resp.json()["share_url"]).group(1)
    # Legacy storage: the completed PDF operation's key carries the
    # noncanonical uppercase report segment.
    _rewrite_pdf_op_key(auth_env, user_id, f"pdf-{str(rid).upper()}")
    # The PDF artifact expires (T6): the share PDF route must return
    # the identical 404, NOT regenerate the PDF on the fly — the
    # on-the-fly path applies only when no PDF was ever generated.
    with auth_env.sessions() as db:
        pdf_result = db.query(M.Result).filter(
            M.Result.user_id == user_id, M.Result.type == "pdf").one()
        pdf_result.expires_at = C._utcnow() - timedelta(minutes=1)
        db.commit()
    baseline = anon.get(f"/s/{'0' * 64}/pdf")
    assert baseline.status_code == 404
    got = anon.get(f"/s/{token}/pdf")
    assert got.status_code == 404
    assert got.content == baseline.content


# --- Follow-up F1: PDF confirmation gates the fetch (contract) ---------------

def test_pdf_confirmation_gates_fetch_on_report_page(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    text = page.text
    # Unconfirmed submit stops the later-registered PDF fetch listener.
    assert "e.stopImmediatePropagation();" in text
    # Continue re-dispatches through the submit event (so the PDF
    # fetch handler performs the download), exactly once.
    assert "confirmedForm.requestSubmit();" in text
    assert "pending.submit()" not in text
    # The confirmed flag is cleared on the confirmed pass, so a
    # later export asks again.
    assert "delete f.dataset.confirmed;" in text
    # The confirm listener is registered before the PDF fetch listener.
    assert text.index("form[data-confirm]") < text.index('form[action$="/pdf"]')


def test_pdf_confirmation_gates_fetch_on_reports_page(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    text = page.text
    assert "e.stopImmediatePropagation();" in text
    assert "confirmedForm.requestSubmit();" in text
    assert "pending.submit()" not in text
    assert "delete f.dataset.confirmed;" in text
    assert text.index("form[data-confirm]") < text.index('form[action$="/pdf"]')


# --- Follow-up F2: share controls update in place (contract) -----------------

def test_report_page_renders_all_share_controls_when_inactive(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    text = page.text
    # All three controls are rendered even with no active link;
    # rotate/revoke start hidden, create visible.
    assert 'id="share-create"' in text
    assert 'id="share-rotate" style="display:none"' in text
    assert 'id="share-revoke" style="display:none"' in text
    # Create/revoke success toggles visibility immediately.
    assert "function setShareButtons(active)" in text
    assert "setShareButtons(true);" in text
    assert "setShareButtons(false);" in text


def test_report_page_renders_all_share_controls_when_active(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    _create_share_token(auth_env, rid, csrf)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    text = page.text
    # With an active link, create is rendered too (hidden), so a
    # revoke in the popup can surface it without a reload.
    assert 'id="share-create" style="display:none"' in text
    assert 'id="share-rotate"' in text
    assert 'id="share-revoke"' in text
    assert "function setShareButtons(active)" in text
    assert "setShareButtons(true);" in text
    assert "setShareButtons(false);" in text


def test_reports_page_share_callbacks_toggle_popup_buttons(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    text = page.text
    # The still-open popup's buttons toggle on create/revoke success.
    assert "function setShareButtons(active)" in text
    assert "setShareButtons(true);" in text
    assert "setShareButtons(false);" in text
