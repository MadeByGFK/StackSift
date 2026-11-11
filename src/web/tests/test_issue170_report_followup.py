"""Issue #170 report follow-up slice (2026-11-11).

Founder ruling 2026-11-10 + fidelity spec 2026-11-11:

- State A/B: the bare "Analysis" cluster button is REMOVED; the
  premium card's "Get the Investigation Report" CTA opens
  #analysis-modal directly (no #analysis-btn forwarding anywhere).
- State B: the premium card now renders when analysis_prior_exists
  (its CTA is that state's only modal entry); the prior-exists
  disclosure stays in the modal copy.
- State C: the completed-report view link is renamed
  "Investigation Report" (href unchanged).
- The post-checkout banner points at "Get the Investigation
  Report", not the removed control.
- G13 completion: the log-window strip renders the formatted
  log_window_label computed in service.py (full / degraded forms),
  falling back to the raw bounds when no label exists.

TEETH: every test in this file FAILS on the pristine base tree
(f0e09d5c) and passes on the built tree — verified by running this
file against both trees. The Node tests drive the REAL inline
scripts from report.html (main actions script + premium-card
script) in the #136/#177 harness style; the harness El.click() is
a no-op stub, so the base tree's card->#analysis-btn forwarding
cannot open the modal there, while the built tree's direct wiring
can.
"""

import json
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app import main
from app.main import templates

_TEMPLATES = Path(main.__file__).parent / "templates"

NONE_MSG = (
    "No active incident established from the available log evidence. "
    "No escalation was detected in this log. This does not guarantee "
    "the system is healthy — persistent issues may not produce "
    "spikes.")


# --- G13 helper: fidelity.log_window_label -----------------------------------


def test_log_window_label_full_form():
    from app import fidelity
    assert fidelity.log_window_label(
        "2026-10-20T09:00:00.000Z", "2026-10-20T10:00:00.000Z") == (
        "Log window 09:00–10:00 UTC · Oct 20, 2026 · 60 minutes analyzed")
    # Founder-screenshot payload shape: fractional seconds dropped,
    # duration rounded to the nearest minute.
    assert fidelity.log_window_label(
        "2026-10-10T18:00:00.000Z", "2026-10-10T19:14:59.999Z") == (
        "Log window 18:00–19:14 UTC · Oct 10, 2026 · 75 minutes analyzed")
    # Non-UTC offsets are projected to UTC.
    assert fidelity.log_window_label(
        "2026-10-20T11:00:00+02:00", "2026-10-20T12:00:00+02:00") == (
        "Log window 09:00–10:00 UTC · Oct 20, 2026 · 60 minutes analyzed")
    # Datetime objects are accepted too.
    start = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
    assert fidelity.log_window_label(start, start + timedelta(hours=1)) == (
        "Log window 09:00–10:00 UTC · Oct 20, 2026 · 60 minutes analyzed")


def test_log_window_label_singular_and_reversed_and_degraded():
    from app import fidelity
    assert fidelity.log_window_label(
        "2026-10-20T09:00:00Z", "2026-10-20T09:01:00Z") == (
        "Log window 09:00–09:01 UTC · Oct 20, 2026 · 1 minute analyzed")
    # end < start: the duration segment is omitted, never negative.
    assert fidelity.log_window_label(
        "2026-10-20T10:00:00Z", "2026-10-20T09:00:00Z") == (
        "Log window 10:00–09:00 UTC · Oct 20, 2026")
    # Time-only bounds: degraded form — no invented date/duration.
    assert fidelity.log_window_label("09:00:00", "09:59:00") == (
        "Log window 09:00–09:59 UTC")
    assert fidelity.log_window_label("09:00", "09:05") == (
        "Log window 09:00–09:05 UTC")


def test_log_window_label_unparseable_returns_none():
    from app import fidelity
    assert fidelity.log_window_label("n/a", "n/a") is None
    assert fidelity.log_window_label(None, None) is None
    assert fidelity.log_window_label("2026-10-20T09:00:00Z", None) is None
    # Mixed full / time-only bounds cannot be labelled honestly.
    assert fidelity.log_window_label(
        "2026-10-20T09:00:00Z", "09:59:00") is None
    # A bare date carries no time — never fabricate a midnight bound.
    assert fidelity.log_window_label("2026-10-20", "2026-10-20") is None


def test_service_context_carries_log_window_label():
    from app import fidelity
    from app.sample_data import SAMPLE_FILENAME, SAMPLE_LOG
    from app.service import analyze_upload
    payload = analyze_upload(SAMPLE_FILENAME, SAMPLE_LOG.encode(),
                             use_alarm=False)
    # KeyError on the base tree (no label computed there) = teeth.
    label = payload["log_window_label"]
    assert label == fidelity.log_window_label(
        payload["first_seen"], payload["last_seen"])
    if label is not None:
        assert label.startswith("Log window ")


# --- Template composition -----------------------------------------------------


def _ctx(**overrides):
    ctx = {
        "filename": "x.log", "elapsed": 0.5,
        "detected_format": "text", "adapted": False,
        "health": {"label": "Critical", "color": "red"},
        "results": {"total_lines": 200, "parsed_lines": 190,
                    "malformed_lines": 10,
                    "level_counts": {"ERROR": 5},
                    "service_counts": {"db": 4}},
        "sorted_issues": [
            ["db timeout", {"level": "ERROR", "count": 7,
                            "services": ["db"]}],
            ["cache miss", {"level": "WARN", "count": 3,
                            "services": ["api"]}],
        ],
        "top_issue": ("cache miss", {"level": "WARN", "count": 3,
                                     "services": ["api"],
                                     "first_seen": "09:01:00"}),
        "diagnostic_issue": ("db timeout",
                             {"level": "ERROR", "count": 7,
                              "services": ["HikariPool-1"],
                              "first_seen": "09:20:14"}),
        "diagnostic_explanation": ["telemetry shows 1/2 pressure signals"],
        "incident_section": {"type": "none", "headline": None,
                             "message": NONE_MSG},
        "notable_events": [{"template": "rare critical",
                            "level": "CRITICAL", "count": 2,
                            "source": "api"}],
        "timeline": [
            {"label": "09:00", "warn": 1, "error": 0, "critical": 0,
             "total": 1},
            {"label": "09:05", "warn": 0, "error": 2, "critical": 0,
             "total": 2},
        ],
        "timeline_caption": ("3 warnings + errors across the window "
                             "09:00–09:05 UTC; peak of 2 at 09:05."),
        "first_seen": "09:00:00", "last_seen": "09:59:00",
        "complexity_truncated": False, "complexity_notice": None,
        "current_user": None, "csrf_token": "t", "report_id": None,
        "ss_id": "SS-20261110-0007",
        "analysis_timestamp": "Nov 10, 2026 · 14:32 UTC",
    }
    ctx.update(overrides)
    return ctx


def _render(**overrides):
    return templates.env.get_template("report.html").render(
        **_ctx(**overrides))


def _owned(**overrides):
    base = {
        "current_user": object(), "report_id": "r1",
        "export_unlocked": False, "share_formats": [],
        "share_create_key": "a", "share_rotate_key": "b",
        "share_revoke_key": "c", "analysis_eligible": True,
        "analysis_reason": None, "analysis_result_id": None,
    }
    base.update(overrides)
    return _render(**base)


def test_g13_render_label_when_present_raw_fallback_when_absent():
    labelled = _render(log_window_label="Log window 09:00–09:59 UTC")
    assert 'data-s1-window' in labelled
    assert "Log window 09:00–09:59 UTC" in labelled
    assert "Log window 09:00:00 – 09:59:00" not in labelled
    # Fallback (guard, same test): with no label the raw strip is
    # rendered exactly as before — never a fabricated format.
    raw = _render(log_window_label=None)
    assert "Log window 09:00:00 – 09:59:00" in raw


def test_state_b_render_card_present_with_prior_exists():
    html = _owned(analysis_prior_exists=True)
    # The card renders in the prior-exists state (it did not on base).
    assert "data-s1-premium-card" in html
    assert 'id="premium-upsell-btn"' in html
    assert "Get the Investigation Report — $9" in html
    # Card terms paragraph verbatim (no prior-exists text added).
    assert "Investigation Report costs $9, paid by card at checkout." in html
    # The disclosure lives in the modal the CTA opens.
    assert "A previous Investigation Report exists for this report." in html
    assert "Generating a new Investigation Report is a new $9 purchase." in html
    # No cluster purchase button remains in this state.
    assert 'id="analysis-btn"' not in html
    assert 'id="analysis-modal"' in html


def test_state_c_render_renamed_link_and_banner_strings():
    html = _owned(analysis_result_id="derived-1")
    cluster = html[html.index('data-s1-actions'):
                   html.index('id="analysis-modal"')]
    assert 'href="/reports/derived-1"' in cluster
    assert ">Investigation Report</a>" in cluster
    assert ">Analysis</a>" not in cluster
    assert 'id="analysis-btn"' not in html
    # Banner (item 6 rename): the checkout-return strings point at
    # the card CTA, never at the removed control.
    banner_html = _owned(checkout_poll=True)
    assert ("Use Get the Investigation Report on this report."
            in banner_html)
    assert ("try again from Get the Investigation Report on this report."
            in banner_html)
    assert "Use Analysis on this report." not in banner_html
    assert "from Analysis on this report." not in banner_html
    # No bare "Analysis" control anywhere in the State A render.
    state_a = _owned()
    assert ">Analysis</button>" not in state_a
    assert ">Analysis</a>" not in state_a
    assert 'id="analysis-btn"' not in state_a


# --- Runtime interaction tests (Node harness over the real scripts) ----------

pytestmark_js = pytest.mark.skipif(
    shutil.which("node") is None, reason="node required for template JS tests")

_HARNESS = r"""
'use strict';
class El {
  constructor(id) {
    this.id = id || ''; this.style = {}; this.textContent = '';
    this.value = ''; this.href = ''; this.dataset = {};
    this.attrs = {}; this.listeners = {}; this.checked = false;
    this.disabled = false;
  }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  select() {}
  requestSubmit() {}
  appendChild() {}
  remove() {}
  click() {}
}
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
['ss-confirm','ss-confirm-text','ss-confirm-yes','ss-confirm-no',
 'share-modal','share-msg','share-link-row','share-link','share-mailto',
 'share-create','share-rotate','share-revoke','share-close',
 'share-btn','share-copy','analysis-modal','analysis-msg',
 'analysis-link-row','analysis-view','analysis-close','analysis-confirm',
 'premium-upsell-btn'].forEach(byId);
const radios = ['txt','pdf','json','csv'].map(function (v) {
  const r = new El('radio-' + v); r.value = v; r.name = 'share-format'; return r;
});
radios[0].checked = true;
const EXPORT_CONFIRM_TEXT = 'Export costs 2 credits and unlocks PDF, CSV and JSON for this report.';
function fireSubmit(form) {
  const ev = {
    defaultPrevented: false,
    preventDefault: function () { this.defaultPrevented = true; },
    stopImmediatePropagation: function () {},
  };
  (form.listeners.submit || []).slice().forEach(function (fn) { fn(ev); });
  if (!ev.defaultPrevented) { form.submittedCount = (form.submittedCount || 0) + 1; }
  return ev;
}
const exportForm = {
  id: 'export-form',
  style: {},
  textContent: '',
  value: '',
  href: '',
  dataset: {},
  attrs: { 'data-confirm': EXPORT_CONFIRM_TEXT },
  listeners: {},
  checked: false,
  disabled: false,
  submittedCount: 0,
  addEventListener: function (ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },
  setAttribute: function (k, v) { this.attrs[k] = String(v); },
  getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
  select: function () {},
  appendChild: function () {},
  remove: function () {},
  click: function () {},
  requestSubmit: function () { fireSubmit(this); },
};
globalThis.exportForm = exportForm;
globalThis.fireSubmit = fireSubmit;
globalThis.EXPORT_CONFIRM_TEXT = EXPORT_CONFIRM_TEXT;
const requested = [];
const docListeners = {};
const fetchCalls = [];
let fetchBody = {};
globalThis.window = globalThis;
globalThis.location = { origin: 'https://example.test' };
globalThis.navigator = {};
globalThis.FormData = class {
  constructor() { this._map = {}; }
  append(k, v) { this._map[k] = v; }
  get(k) { return Object.prototype.hasOwnProperty.call(this._map, k) ? this._map[k] : null; }
};
globalThis.document = {
  getElementById: function (id) { requested.push(id); return byId(id); },
  addEventListener: function (ev, fn) { (docListeners[ev] = docListeners[ev] || []).push(fn); },
  querySelectorAll: function (sel) {
    if (sel === 'form[data-confirm]') { return [exportForm]; }
    if (sel === 'input[name="share-format"]') { return radios; }
    return [];
  },
  querySelector: function (sel) {
    if (sel === 'input[name="share-format"]:checked') {
      return radios.find(function (r) { return r.checked; }) || null;
    }
    return null;
  },
};
globalThis.fetch = function (url, opts) {
  fetchCalls.push({ url: url, method: (opts && opts.method) || 'GET' });
  return Promise.resolve({
    ok: true, status: 200,
    json: function () { return Promise.resolve(fetchBody); },
  });
};
function fireEscape() {
  (docListeners['keydown'] || []).forEach(function (fn) {
    fn({ key: 'Escape', preventDefault: function () {} });
  });
}
async function flush() { for (let i = 0; i < 8; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
async function click(el) {
  (el.listeners.click || []).forEach(function (fn) {
    fn({ preventDefault: function () {}, stopImmediatePropagation: function () {} });
  });
  await flush();
}
"""


def _script_with(marker):
    html = (_TEMPLATES / "report.html").read_text()
    for script in re.findall(r"<script>(.*?)</script>", html, re.S):
        if marker in script:
            return script
    raise AssertionError(f"script with {marker!r} not found in report.html")


def _followup_scripts():
    main_script = _script_with("ss-confirm")
    main_script = main_script.replace("{{ share_create_key }}", "create-key")
    main_script = main_script.replace("{{ share_rotate_key }}", "rotate-key")
    main_script = main_script.replace("{{ share_revoke_key }}", "revoke-key")
    main_script = main_script.replace("{{ csrf_token }}", "csrf-test")
    main_script = main_script.replace("{{ report_id }}", "RID")
    main_script = re.sub(r"var shareActiveFormats = .*?;",
                         "var shareActiveFormats = [];", main_script,
                         count=1, flags=re.S)
    card_script = _script_with("premium-upsell-btn")
    combined = main_script + "\n" + card_script
    assert "{{" not in combined, "unreplaced jinja left in harness scripts"
    return combined


def _run_js(scenario):
    full = (_HARNESS + "\n" + _followup_scripts()
            + "\n(async () => {\n  const out = {};\n" + scenario
            + "\n  console.log('RESULT:' + JSON.stringify(out));\n"
            "})().catch(function (e) { console.error(e && e.stack || e); "
            "process.exit(3); });\n")
    proc = subprocess.run(["node", "-e", full], capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 0, \
        f"node harness failed:\n{proc.stdout}\n{proc.stderr}"
    line = next(l for l in proc.stdout.splitlines()
                if l.startswith("RESULT:"))
    return json.loads(line[len("RESULT:"):])


@pytestmark_js
def test_runtime_1_card_cta_opens_modal_directly_no_analysis_btn():
    out = _run_js("""
      await click(byId('premium-upsell-btn'));
      out.modalAfterCard = byId('analysis-modal').style.display || '';
      out.requestedAnalysisBtn = requested.indexOf('analysis-btn') !== -1;
      out.fetchCount = fetchCalls.length;
    """)
    assert out["modalAfterCard"] == "flex", out
    # No forwarding: neither script ever looks up #analysis-btn.
    assert out["requestedAnalysisBtn"] is False, out
    assert out["fetchCount"] == 0, out


@pytestmark_js
def test_runtime_2_cancel_escape_no_state_confirm_path_unchanged():
    out = _run_js("""
      await click(byId('premium-upsell-btn'));
      out.opened = byId('analysis-modal').style.display || '';
      fireEscape();
      await flush();
      out.afterEscape = byId('analysis-modal').style.display || '';
      out.fetchAfterEscape = fetchCalls.length;
      await click(byId('analysis-close'));
      out.afterCancel = byId('analysis-modal').style.display || '';
      out.fetchAfterCancel = fetchCalls.length;
      out.confirmDisabledAfterCancel = !!byId('analysis-confirm').disabled;
      out.msgAfterCancel = byId('analysis-msg').textContent || '';
      fetchBody = { report_url: '/reports/derived-9' };
      await click(byId('premium-upsell-btn'));
      await click(byId('analysis-confirm'));
      out.confirmFetchCount = fetchCalls.length;
      out.confirmFetchUrl = fetchCalls.length ? fetchCalls[0].url : '';
      out.confirmFetchMethod = fetchCalls.length ? fetchCalls[0].method : '';
      out.msgAfterConfirm = byId('analysis-msg').textContent || '';
      out.viewHref = byId('analysis-view').href || '';
      out.linkRowDisplay = byId('analysis-link-row').style.display || '';
      out.confirmDisplay = byId('analysis-confirm').style.display || '';
    """)
    assert out["opened"] == "flex", out
    # Escape dispatches no handler in this template (pre-existing):
    # it changes no state — modal untouched, nothing fetched.
    assert out["afterEscape"] == "flex", out
    assert out["fetchAfterEscape"] == 0, out
    # Cancel closes and changes no state (no fetch, Confirm armed,
    # message untouched).
    assert out["afterCancel"] == "none", out
    assert out["fetchAfterCancel"] == 0, out
    assert out["confirmDisabledAfterCancel"] is False, out
    assert out["msgAfterCancel"] == "", out
    # Confirm path unchanged: same POST route, success shows the
    # ready message + view link and hides Confirm.
    assert out["confirmFetchCount"] == 1, out
    assert out["confirmFetchUrl"] == "/reports/RID/deep-dive", out
    assert out["confirmFetchMethod"] == "POST", out
    assert out["msgAfterConfirm"] == "Investigation Report ready.", out
    assert out["viewHref"] == "/reports/derived-9", out
    assert out["linkRowDisplay"] == "block", out
    assert out["confirmDisplay"] == "none", out


@pytestmark_js
def test_runtime_3_state_b_card_cta_opens_modal_with_disclosure():
    # Render half (State B): card present, disclosure in the modal.
    html = _owned(analysis_prior_exists=True)
    assert "data-s1-premium-card" in html
    assert "A previous Investigation Report exists for this report." in html
    # Runtime half: the card CTA opens that modal.
    out = _run_js("""
      await click(byId('premium-upsell-btn'));
      out.modalAfterCard = byId('analysis-modal').style.display || '';
    """)
    assert out["modalAfterCard"] == "flex", out


@pytestmark_js
def test_runtime_5_export_share_unaffected_after_modal_open_close():
    out = _run_js("""
      await click(byId('premium-upsell-btn'));
      out.opened = byId('analysis-modal').style.display || '';
      await click(byId('analysis-close'));
      out.closed = byId('analysis-modal').style.display || '';
      await click(byId('share-btn'));
      out.shareOpened = byId('share-modal').style.display || '';
      out.shareMsg = byId('share-msg').textContent || '';
      await click(byId('share-close'));
      out.shareClosed = byId('share-modal').style.display || '';
      await click(byId('premium-upsell-btn'));
      out.reopened = byId('analysis-modal').style.display || '';
      out.confirmModalBeforeExport = byId('ss-confirm').style.display || '';
      out.fetchCount = fetchCalls.length;
      // Export confirm flow, driven through the REAL ss-confirm
      // handlers registered on the fake form[data-confirm] form:
      // (a) a direct submit is intercepted — modal opens with the
      // form's data-confirm text and nothing is submitted.
      fireSubmit(exportForm);
      out.exportModalAfterSubmit = byId('ss-confirm').style.display || '';
      out.exportConfirmText = byId('ss-confirm-text').textContent || '';
      out.exportSubmittedAfterSubmit = exportForm.submittedCount;
      // (b) Cancel closes the modal and still submits nothing.
      await click(byId('ss-confirm-no'));
      out.exportModalAfterNo = byId('ss-confirm').style.display || '';
      out.exportSubmittedAfterNo = exportForm.submittedCount;
      // (c) Submit again, then Yes: the confirmed re-submit passes
      // through the handler exactly once, the modal does not
      // re-open, and dataset.confirmed is consumed/cleared.
      fireSubmit(exportForm);
      out.exportModalAfterResubmit = byId('ss-confirm').style.display || '';
      out.exportSubmittedBeforeYes = exportForm.submittedCount;
      await click(byId('ss-confirm-yes'));
      out.exportSubmittedAfterYes = exportForm.submittedCount;
      out.exportModalAfterYes = byId('ss-confirm').style.display || '';
      out.exportConfirmedCleared = !('confirmed' in exportForm.dataset);
    """)
    assert out["opened"] == "flex", out
    assert out["closed"] == "none", out
    # Share control still opens its modal with its state untouched.
    assert out["shareOpened"] == "flex", out
    assert out["shareMsg"] == "", out
    assert out["shareClosed"] == "none", out
    # Card CTA still works after the share cycle; the export
    # data-confirm modal was not triggered by that cycle alone;
    # nothing was fetched.
    assert out["reopened"] == "flex", out
    assert out["confirmModalBeforeExport"] != "flex", out
    assert out["fetchCount"] == 0, out
    # (a) Export submit is gated by the real confirm handler.
    assert out["exportModalAfterSubmit"] == "flex", out
    assert out["exportConfirmText"] == (
        "Export costs 2 credits and unlocks PDF, CSV and JSON "
        "for this report."), out
    assert out["exportSubmittedAfterSubmit"] == 0, out
    # (b) Cancel: modal closes, no submission.
    assert out["exportModalAfterNo"] == "none", out
    assert out["exportSubmittedAfterNo"] == 0, out
    # (c) Yes: exactly one real submission, modal stays closed,
    # and the one-shot confirmed flag is cleared by the handler.
    assert out["exportModalAfterResubmit"] == "flex", out
    assert out["exportSubmittedBeforeYes"] == 0, out
    assert out["exportSubmittedAfterYes"] == 1, out
    assert out["exportModalAfterYes"] == "none", out
    assert out["exportConfirmedCleared"] is True, out
