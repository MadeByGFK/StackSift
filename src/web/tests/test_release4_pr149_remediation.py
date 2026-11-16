"""Release #4 / PR #149 remediation: two Codex P2s on head 909ad9f7.

Codex review of record on the release PR produced two P2 findings,
both verified by Sunny against the code:

F1. The fresh-analysis response rendered report.html without the
    Analysis action state. _analysis_response supplied report_id but
    neither analysis_eligible nor analysis_reason (populated only by
    the saved-report and My Reports routes), so for a signed-in user
    immediately after a successful upload, Actions -> Analysis opened
    a popup containing only Cancel — even when the new report was
    eligible. Fix: _analysis_response populates the same state the
    saved-report page sets (eligibility from the retained-evidence
    contract over the render's own payload; a completed generation
    links straight to the derived report).

F2. deep_dive._symptom_and_cause asserted a timeout incident from a
    bare "timeout" substring. Configuration/negation messages such
    as "Request timeout disabled; operations will wait indefinitely"
    were explained in the PAID Analysis Report as operations that
    timed out. Fix: the F1 pattern — require failure semantics and
    veto configuration/negation shapes; unsupported shapes fall
    through to the default/abstention explanation.

TEETH: every test in this file FAILS on the pre-fix tree and PASSES
on the fixed tree, except the explicitly labelled controls, which
pass on both trees by design and pin the unchanged behaviour.
"""

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from app import deep_dive as dd
from app.sample_data import SAMPLE_LOG


# --- F2: timeout predicate ---------------------------------------------------

_DEFAULT_MARKER = "no further symptom detail is established"
_TIMEOUT_MARKER = "operations that timed out"


def _symptom_cause(template):
    symptom, cause, _check = dd._symptom_and_cause(template, [])
    return symptom, cause


def test_f2_timeout_disabled_config_does_not_claim_timeout():
    # The Codex counterexample, verbatim.
    symptom, cause = _symptom_cause(
        "Request timeout disabled; operations will wait indefinitely")
    assert _DEFAULT_MARKER in symptom
    assert cause is None


def test_f2_no_timeout_occurred_does_not_claim_timeout():
    symptom, cause = _symptom_cause(
        "Health check passed: no timeout occurred during the run")
    assert _DEFAULT_MARKER in symptom
    assert cause is None


def test_f2_timeout_value_assignment_does_not_claim_timeout():
    symptom, cause = _symptom_cause("Configured request timeout: 30s")
    assert _DEFAULT_MARKER in symptom
    assert cause is None


def test_f2_generator_abstains_for_timeout_disabled_template():
    # End-to-end through the generator: the group's possible cause
    # is the ruled abstention, not a timeout claim.
    from app.service import analyze_upload
    data = analyze_upload(
        "cfg.log",
        b"2024-01-01 10:00:00 WARN Request timeout disabled; "
        b"operations will wait indefinitely\n"
        b"2024-01-01 10:00:01 WARN Request timeout disabled; "
        b"operations will wait indefinitely\n")
    assert "error" not in data, data
    artifact = dd.build_deep_dive(data)
    (group,) = artifact["groups"]
    assert [c["text"] for c in group["possible_causes"]] == [dd.ABSTENTION]
    assert "timed out" not in group["explanations"][0]["text"]


# F2 controls (pass on both trees): genuine timeout failures keep
# their specific, bounded explanation.

def test_f2_control_connection_timed_out_keeps_timeout_explanation():
    symptom, cause = _symptom_cause("Connection timed out after 30s")
    assert _TIMEOUT_MARKER in symptom
    assert cause is not None and "does not establish" in cause


def test_f2_control_timeout_error_keeps_timeout_explanation():
    symptom, cause = _symptom_cause("Gateway timeout error from upstream")
    assert _TIMEOUT_MARKER in symptom
    assert cause is not None


def test_f2_control_timeout_exceeded_keeps_timeout_explanation():
    symptom, cause = _symptom_cause(
        "Request failed: timeout exceeded the configured limit")
    assert _TIMEOUT_MARKER in symptom
    assert cause is not None


# --- F1: fresh-response Analysis action state --------------------------------

# PREMISE CHANGED (#164 Phase A): the fresh-response modal carries
# the ruled dollar copy, and it renders on the price-configured
# surface (the fail-closed "Coming soon" state otherwise) — so this
# module pins the product Price env for its rendering tests.
import os as _os
_os.environ.setdefault("STRIPE_PRICE_INVESTIGATION_REPORT",
                       "price_test_investigation")

_COST_MSG = "Investigation Report costs $9"


def _fresh_upload(env, content, filename="test.log"):
    return env.client.post(
        "/analyze",
        files={"file": (filename, content)},
        data={"request_id": uuid.uuid4().hex, "output": "html"})


def test_f1_fresh_response_shows_analysis_cost_for_eligible_report(env):
    resp = _fresh_upload(env, SAMPLE_LOG.encode())
    assert resp.status_code == 200, resp.text[:300]
    # Pre-fix this render had neither variable set: the modal fell
    # into the ineligible branch with an empty reason, so the cost
    # copy (and the Generate button) never appeared.
    assert _COST_MSG in resp.text
    assert 'id="analysis-confirm"' in resp.text


def test_f1_fresh_response_replay_shows_analysis_cost_too(env):
    request_id = uuid.uuid4().hex
    form = {"request_id": request_id, "output": "html"}
    files = {"file": ("test.log", SAMPLE_LOG.encode())}
    first = env.client.post("/analyze", files=files, data=form)
    assert first.status_code == 200, first.text[:300]
    replay = env.client.post("/analyze", files=files, data=form)
    assert replay.status_code == 200, replay.text[:300]
    assert _COST_MSG in replay.text
    assert 'id="analysis-confirm"' in replay.text


def test_f1_fresh_response_shows_reason_for_ineligible_report(
        env, monkeypatch):
    # The env fixture's stubbed analyzer always yields an eligible
    # payload, so the ineligible branch is exercised by pinning the
    # state provider to a sentinel reason: the wiring under test is
    # that _analysis_response consults it and renders its reason
    # (pre-fix it never calls it, and the modal reason is empty).
    monkeypatch.setattr(
        dd, "eligibility_state",
        lambda payload: (False, "SENTINEL-INELIGIBLE-REASON"))
    resp = _fresh_upload(env, SAMPLE_LOG.encode())
    assert resp.status_code == 200, resp.text[:300]
    assert "SENTINEL-INELIGIBLE-REASON" in resp.text
    # #164: the negative assertion targets the rendered modal copy
    # (the full dollar terms sentence) — a short JS error-fallback
    # literal elsewhere in the page is not the modal copy.
    assert "Investigation Report costs $9, paid by card at checkout" \
        not in resp.text
