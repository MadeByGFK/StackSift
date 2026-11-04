"""Issue #106 Stage 2 / PR #139 remediation round 1: four Codex P2s.

Codex review of record on PR #139 head 138eec5 produced four P2
findings, all verified by Sunny against the code:

F1. deep_dive._symptom_and_cause predicates were over-broad and
    asserted unsupported claims in a PAID report: a bare "refused"
    claimed refused network connections ("Payment refused by fraud
    policy") and a bare "exhausted" / pool+connection claimed pool
    exhaustion ("Disk space exhausted", "Connection pool
    reconfigured successfully"). Fix: require BOTH relevant context
    AND failure semantics; otherwise fall through to the
    default/abstention explanation.
F2. My Reports rendered a Share button on Analysis Report
    (deep_dive) rows, but _share_owner_gate admits only
    analysis/comparison, so it always 404'd. Fix: suppress Share
    on deep_dive rows in reports.html (mirroring Extend), retain
    the server-side rejection.
F3. The My Reports Analysis popup wrote fetch responses to the
    shared modal without checking the popup still belonged to the
    originating report — a stale response for report A overwrote
    report B's popup. Fix: capture the originating button/report
    at request start and ignore stale responses, mirroring the
    share popup's PR #132 finding 6 pattern.
F4. credits.completed_analysis_result_id returned the derived
    Analysis Report id without checking the derived Result's
    availability; an expired/deleted derived report (its own
    7-day life, even when the source is retention-extended) was
    linked straight to a 410. Fix: return the id only when the
    derived Result exists, is not deleted, and is not expired.

TEETH: every test in this file FAILS on the pre-fix tree and
PASSES on the fixed tree, except the explicitly labelled controls
(the F1 legitimate-case tests, the F3 no-switch control, and the
F4 live-derived control), which pass on both trees by design and
pin the unchanged behaviour.
"""

import json
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import _setup
from app import credits as C
from app import deep_dive as dd
from app import main


# --- F1: explanation predicates ---------------------------------------------

_DEFAULT_MARKER = "no further symptom detail is established"


def _symptom_cause(template):
    symptom, cause, _check = dd._symptom_and_cause(template, [])
    return symptom, cause


def test_f1_payment_refused_by_fraud_policy_does_not_claim_connection_refused():
    symptom, cause = _symptom_cause("Payment refused by fraud policy")
    assert _DEFAULT_MARKER in symptom
    assert cause is None  # caller renders the abstention sentence


def test_f1_disk_space_exhausted_does_not_claim_pool_exhaustion():
    symptom, cause = _symptom_cause("Disk space exhausted")
    assert _DEFAULT_MARKER in symptom
    assert cause is None


def test_f1_pool_reconfigured_successfully_does_not_claim_pool_exhaustion():
    symptom, cause = _symptom_cause(
        "Connection pool reconfigured successfully")
    assert _DEFAULT_MARKER in symptom
    assert cause is None


def test_f1_generator_abstains_for_payment_refused_template():
    # End-to-end through the generator: the group's possible cause
    # is the ruled abstention, not a refused-connection claim.
    from app.service import analyze_upload
    data = analyze_upload(
        "pay.log",
        b"2024-01-01 10:00:00 ERROR Payment refused by fraud policy\n"
        b"2024-01-01 10:00:01 ERROR Payment refused by fraud policy\n")
    assert "error" not in data, data
    artifact = dd.build_deep_dive(data)
    (group,) = artifact["groups"]
    assert [c["text"] for c in group["possible_causes"]] == [dd.ABSTENTION]
    assert "refused by the destination" not in group["explanations"][0]["text"]


# F1 controls (pass on both trees): legitimate shapes keep their
# specific, bounded explanations.

def test_f1_control_connection_refused_by_host_keeps_refused_explanation():
    symptom, cause = _symptom_cause("Connection refused by host")
    assert "were refused by the destination" in symptom
    assert cause is not None and "does not establish why" in cause


def test_f1_control_connection_to_host_refused_keeps_refused_explanation():
    symptom, cause = _symptom_cause(
        "DatabaseError: connection to db-01 refused")
    assert "were refused by the destination" in symptom
    assert cause is not None


def test_f1_control_connection_pool_exhausted_keeps_pool_explanation():
    symptom, cause = _symptom_cause("connection pool exhausted")
    assert "resource pool" in symptom and "exhausted" in symptom
    assert cause is not None and "Pool exhaustion" in cause


def test_f1_control_pool_exhausted_no_connections_keeps_pool_explanation():
    symptom, cause = _symptom_cause(
        "Pool exhausted: no connections available")
    assert "resource pool" in symptom and "exhausted" in symptom
    assert cause is not None and "Pool exhaustion" in cause


# --- F2 + F4: My Reports rows / derived-result availability ------------------

def _generate(auth_env, rid, csrf):
    return auth_env.client.post(
        f"/reports/{rid}/deep-dive", data={"csrf_token": csrf})


def _card_for(page_text, report_id):
    cards = page_text.split('<li class="card">')
    view_link = f'href="/reports/{report_id}" class="btn btn-ghost">View'
    matches = [c for c in cards if view_link in c]
    assert len(matches) == 1, report_id
    return matches[0]


def test_f2_deep_dive_row_has_no_share_button_but_normal_row_does(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    analysis_id = gen.json()["analysis_result_id"]
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    normal_card = _card_for(page.text, str(rid))
    assert "share-open" in normal_card and "Share" in normal_card
    deep_dive_card = _card_for(page.text, analysis_id)
    assert "share-open" not in deep_dive_card
    assert "Share" not in deep_dive_card
    # Retained server-side rejection: creating a share link for an
    # Analysis Report still fails closed (404 via the owner gate).
    share = auth_env.client.post(
        f"/reports/{analysis_id}/share",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert share.status_code == 404, share.text[:300]


def _completed_derived_id(auth_env, user_id, source_id):
    with auth_env.sessions() as db:
        found = C.completed_analysis_result_id(db, user_id, source_id)
    assert found is not None
    return found


def _mutate_derived(auth_env, derived_id, **changes):
    from app import models
    with auth_env.sessions() as db:
        row = db.get(models.Result, derived_id)
        for key, value in changes.items():
            setattr(row, key, value)
        db.commit()


def test_f4_expired_derived_report_is_not_returned(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    derived_id = _completed_derived_id(auth_env, user_id, rid)
    # The retention-extended source outlives the derived report:
    # extend the source far into the future, expire the derived.
    now = datetime.now(timezone.utc)
    from app import models
    with auth_env.sessions() as db:
        source = db.get(models.Result, rid)
        source.expires_at = now + timedelta(days=90)
        db.commit()
    _mutate_derived(auth_env, derived_id,
                    expires_at=now - timedelta(days=1))
    with auth_env.sessions() as db:
        assert C.completed_analysis_result_id(db, user_id, rid) is None
    # The source row therefore shows the normal Analysis action
    # again instead of a direct link that would open a 410.
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    source_card = _card_for(page.text, str(rid))
    assert "analysis-open" in source_card
    assert f'href="/reports/{derived_id}" class="btn btn-ghost">Analysis' \
        not in source_card


def test_f4_deleted_derived_report_is_not_returned(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    derived_id = _completed_derived_id(auth_env, user_id, rid)
    _mutate_derived(auth_env, derived_id,
                    deleted_at=datetime.now(timezone.utc))
    with auth_env.sessions() as db:
        assert C.completed_analysis_result_id(db, user_id, rid) is None


def test_f4_missing_derived_report_is_not_returned(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    derived_id = _completed_derived_id(auth_env, user_id, rid)
    from sqlalchemy import text as _text
    from app import models
    with auth_env.sessions() as db:
        # Delete the derived Result row outright; the completed
        # operation still references its (now missing) id. FK
        # enforcement is per-connection in SQLite, so disable it
        # on THIS session's connection for the deletion only.
        db.execute(_text("PRAGMA foreign_keys=OFF"))
        row = db.get(models.Result, derived_id)
        db.delete(row)
        db.commit()
        db.execute(_text("PRAGMA foreign_keys=ON"))
    with auth_env.sessions() as db:
        assert C.completed_analysis_result_id(db, user_id, rid) is None


def test_f4_control_live_derived_report_is_returned(auth_env):
    # CONTROL (pass on both trees): a live derived report is linked.
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    with auth_env.sessions() as db:
        found = C.completed_analysis_result_id(db, user_id, rid)
    assert found is not None
    assert str(found) == gen.json()["analysis_result_id"]


# --- F3: Analysis popup stale-response race (Node harness) -------------------

pytestmark_js = pytest.mark.skipif(
    shutil.which("node") is None, reason="node required for template JS tests")

_TEMPLATES = Path(main.__file__).parent / "templates"

_HARNESS = r"""
'use strict';
class El {
  constructor(id) {
    this.id = id || ''; this.style = {}; this.textContent = '';
    this.value = ''; this.href = ''; this.dataset = {};
    this.attrs = {}; this.listeners = {}; this.checked = false;
    this.disabled = false; this.children = [];
  }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  appendChild(child) { this.children.push(child); return child; }
  select() {}
  requestSubmit() {}
}
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
['ss-confirm','ss-confirm-text','ss-confirm-yes','ss-confirm-no',
 'share-modal','share-msg','share-link-row','share-link','share-mailto',
 'share-create','share-rotate','share-revoke','share-close','share-copy',
 'analysis-modal','analysis-msg','analysis-link-row','analysis-view',
 'analysis-confirm','analysis-close'].forEach(byId);
const radios = ['txt','pdf','json','csv'].map(function (v) {
  const r = new El('radio-' + v); r.value = v; r.name = 'share-format'; return r;
});
radios[0].checked = true;
const lockNotes = [new El('lock-1'), new El('lock-2'), new El('lock-3')];
const rowBtns = [];
const analysisBtns = [];
globalThis.window = globalThis;
globalThis.location = { origin: 'https://example.test' };
globalThis.document = {
  getElementById: byId,
  createElement: function (tag) { return new El('created-' + tag); },
  createTextNode: function (t) { return { textContent: t, text: t, href: '' }; },
  querySelectorAll: function (sel) {
    if (sel === 'input[name="share-format"]') { return radios; }
    if (sel === '.share-open') { return rowBtns; }
    if (sel === '.analysis-open') { return analysisBtns; }
    if (sel === '.share-lock-note') { return lockNotes; }
    return [];
  },
  querySelector: function (sel) {
    if (sel === 'input[name="share-format"]:checked') {
      return radios.find(function (r) { return r.checked; }) || null;
    }
    const m = sel.match(/\[value="(\w+)"\]/);
    if (m) { return radios.find(function (r) { return r.value === m[1]; }) || null; }
    return null;
  },
};
class FormDataStub {
  constructor() { this.map = {}; }
  append(k, v) { this.map[k] = v; }
  get(k) { return this.map[k]; }
}
globalThis.FormData = FormDataStub;
// DEFERRED fetch: the scenario sets queuedResponse, clicks
// Generate, switches reports, then resolves the fetch manually.
let pendingFetchResolve = null;
let queuedResponse = { status: 200, body: {} };
globalThis.fetch = function (path, opts) {
  const resp = queuedResponse;
  return new Promise(function (resolve) {
    pendingFetchResolve = function () {
      resolve({
        ok: resp.status >= 200 && resp.status < 300, status: resp.status,
        json: function () { return Promise.resolve(resp.body); },
      });
    };
  });
};
async function flush() { for (let i = 0; i < 6; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
async function resolveFetch() {
  if (!pendingFetchResolve) { throw new Error('no pending fetch to resolve'); }
  const r = pendingFetchResolve; pendingFetchResolve = null; r();
  await flush();
}
async function click(el) {
  (el.listeners.click || []).forEach(function (fn) {
    fn({ preventDefault: function () {}, stopImmediatePropagation: function () {} });
  });
  await flush();
}
function snapA() {
  const msg = byId('analysis-msg');
  return {
    msg: msg.textContent || '',
    children: (msg.children || []).map(function (c) {
      return { text: c.textContent || c.text || '', href: c.href || '' };
    }),
    linkRow: byId('analysis-link-row').style.display || '',
    viewHref: byId('analysis-view').href || '',
    confirmDisplay: byId('analysis-confirm').style.display || '',
    confirmDisabled: !!byId('analysis-confirm').disabled,
  };
}
"""

_SCENARIO_TAIL = r"""
  console.log('RESULT:' + JSON.stringify(out));
})().catch(function (e) { console.error(e && e.stack || e); process.exit(3); });
"""

_SETUP_JS = (
    "const btnA = new El('analysis-a');\n"
    "btnA.setAttribute('data-report', 'RID-A');\n"
    "btnA.setAttribute('data-eligible', '1');\n"
    "btnA.setAttribute('data-reason', '');\n"
    "analysisBtns.push(btnA);\n"
    "const btnB = new El('analysis-b');\n"
    "btnB.setAttribute('data-report', 'RID-B');\n"
    "btnB.setAttribute('data-eligible', '1');\n"
    "btnB.setAttribute('data-reason', '');\n"
    "analysisBtns.push(btnB);\n"
)

_COST_MSG = "Analysis Report costs 3 credits"


def _run_analysis_scenario(scenario):
    html = (_TEMPLATES / "reports.html").read_text()
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    script = next(s for s in scripts if "analysisConfirm" in s)
    script = script.replace("{{ csrf_token }}", "csrf-test")
    script = script.replace("{{ analysis_report_cost }}", "3")
    full = (_HARNESS + "\n" + _SETUP_JS + "\n" + script + "\n"
            "(async () => {\n  const out = {};\n" + scenario
            + _SCENARIO_TAIL)
    proc = subprocess.run(
        ["node", "-e", full], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, (
        f"node harness failed:\n{proc.stdout}\n{proc.stderr}")
    line = next(l for l in proc.stdout.splitlines() if l.startswith("RESULT:"))
    return json.loads(line[len("RESULT:"):])


_SWITCH_SCENARIO = """
  await click(btnA);
  queuedResponse = __RESPONSE__;
  await click(byId('analysis-confirm'));
  await click(btnB);
  out.afterSwitch = snapA();
  await resolveFetch();
  out.afterResolve = snapA();
"""


@pytestmark_js
def test_f3_stale_success_response_does_not_overwrite_switched_popup():
    out = _run_analysis_scenario(_SWITCH_SCENARIO.replace(
        "__RESPONSE__",
        "{ status: 200, body: { report_url: '/reports/ANALYSIS-A' } }"))
    after = out["afterResolve"]
    # Report B's popup is untouched: its cost message stays, no
    # result link for A is shown, and B's Generate button is not
    # hidden by A's response.
    assert _COST_MSG in after["msg"], after
    assert after["linkRow"] == "none", after
    assert "ANALYSIS-A" not in after["viewHref"], after
    assert after["confirmDisplay"] == "", after
    assert after["confirmDisabled"] is False, after


@pytestmark_js
def test_f3_stale_failure_response_does_not_overwrite_switched_popup():
    out = _run_analysis_scenario(_SWITCH_SCENARIO.replace(
        "__RESPONSE__",
        "{ status: 500, body: { error: 'Boom failure for A' } }"))
    after = out["afterResolve"]
    assert _COST_MSG in after["msg"], after
    assert "Boom failure for A" not in after["msg"], after
    assert after["linkRow"] == "none", after
    assert after["confirmDisplay"] == "", after


@pytestmark_js
def test_f3_stale_402_response_does_not_overwrite_switched_popup():
    out = _run_analysis_scenario(_SWITCH_SCENARIO.replace(
        "__RESPONSE__",
        "{ status: 402, body: { error: 'Insufficient credits. ', "
        "purchase_url: '/credits' } }"))
    after = out["afterResolve"]
    assert _COST_MSG in after["msg"], after
    # No Buy-credits link/text from A's 402 was appended into B's popup.
    assert after["children"] == [], after
    assert after["confirmDisplay"] == "", after


@pytestmark_js
def test_f3_control_response_without_switch_displays_normally():
    # CONTROL (pass on both trees): with no report switch before
    # the response arrives, the success renders exactly as before.
    out = _run_analysis_scenario("""
      await click(btnA);
      queuedResponse = { status: 200, body: { report_url: '/reports/ANALYSIS-A' } };
      await click(byId('analysis-confirm'));
      await resolveFetch();
      out.afterResolve = snapA();
    """)
    after = out["afterResolve"]
    assert after["msg"] == "Analysis Report ready.", after
    assert after["linkRow"] == "block", after
    assert "ANALYSIS-A" in after["viewHref"], after
    assert after["confirmDisplay"] == "none", after
