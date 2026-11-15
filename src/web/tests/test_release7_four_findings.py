"""Release #7 — Kolby's four hand-check findings (F1-F4): runtime tests.

Spec of record: release7-four-findings/spec.md (Sunny, 2026-11-14),
base aa6220a6. F4 copy APPROVED by Kolby 2026-11-14 21:02 ET.

- F1: the export confirmation popup (data-confirm / ss-confirm) is
  removed from all 9 export forms on report.html, deep_dive_report.html
  and reports.html; exports fire directly. The PDF fetch interception
  in auth_form_script.html must still fire exactly once per click.
- F2: REPRODUCED root cause (staging, 2026-11-14 21:17-21:21 ET) is NOT
  the confirm chain — toggle/menu/modal/interception all worked. The
  break is the PDF serving path in main.py: a report whose stored
  (previously generated) PDF result can no longer be validated got a
  dead-end 410 "Previously generated PDF is no longer available.
  Please generate a new export." with no regeneration action. The fix
  regenerates from the still-valid source report via the unlocked
  fresh-generation path. F1 does NOT fix F2; they are separate fixes.
- F3: "Compare two logs" entry card directly under the Batch card on
  My Reports, element-for-element mirror.
- F4: PAY_NOW_PROMISE replaced by the founder-approved plain-words
  text (single constant); the reports.html inline Investigation
  Report dialog duplicate updated to the same text.

Teeth discipline: tests 1-4 and 7 FAIL on base aa6220a6 and pass on
the built tree; guards 5-6 pass on both. The Node harness implements
faithful event semantics — stopImmediatePropagation HALTS the
remaining listeners on the same element (the #180 lesson: a harness
whose stopImmediatePropagation is a no-op does not exercise the real
chain). Harness forms are synthetic and always carry the base-era
data-confirm attribute: on the built tree no script queries that
selector, so script behaviour is unaffected; the MARKUP premise (no
data-confirm / ss-confirm in the real rendered pages) is pinned
separately against TestClient-rendered pages below.
"""
import html
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from test_issue164_phase_b import p164b_env  # noqa: F401  (fixture)

_TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"

APPROVED_PROMISE = (
    "You pay by card at checkout. If we can't generate your report, "
    "your purchase isn't used up \u2014 you can try again. If a purchase "
    "can never be used, we'll refund it \u2014 email "
    "disputes@goodfolkdigital.com.")
OLD_PROMISE = (
    "Payment is captured at checkout. If generation fails, your "
    "purchase is never consumed \u2014 the entitlement stays available "
    "and you can retry. A purchase that can never be redeemed is "
    "refundable on request via disputes@goodfolkdigital.com.")


# ---------------------------------------------------------------------------
# Script extraction (real template scripts, Jinja placeholders neutralised)
# ---------------------------------------------------------------------------

def _scripts(template_name):
    html = (_TEMPLATES / template_name).read_text()
    return re.findall(r"<script>(.*?)</script>", html, re.S)


def _script_with(template_name, marker, required=True):
    for script in _scripts(template_name):
        if marker in script:
            return script
    if required:
        raise AssertionError(
            f"script with {marker!r} not found in {template_name}")
    return None


def _neutralise(script):
    script = script.replace("{{ share_create_key }}", "create-key")
    script = script.replace("{{ share_rotate_key }}", "rotate-key")
    script = script.replace("{{ share_revoke_key }}", "revoke-key")
    script = script.replace("{{ csrf_token }}", "csrf-test")
    script = script.replace("{{ report_id }}", "RID")
    script = re.sub(r"var shareActiveFormats = .*?;",
                    "var shareActiveFormats = [];", script,
                    count=1, flags=re.S)
    assert "{{" not in script, "unreplaced jinja left in harness script"
    return script


def _auth_script():
    return _script_with("auth_form_script.html", 'form[action$="/pdf"]')


def _page_scripts(page):
    if page == "report":
        parts = [_script_with("report.html", "share-modal")]
        card = _script_with("report.html", "premium-upsell-btn",
                            required=False)
        if card:
            parts.append(card)
        parts.append(_auth_script())
    elif page == "deepdive":
        parts = [s for s in _scripts("deep_dive_report.html")
                 if "ss-confirm" in s or "data-confirm" in s]
        parts.append(_auth_script())
    elif page == "reports":
        parts = [_script_with("reports.html", "s3CloseMenus"),
                 _script_with("reports.html", "analysisConfirm"),
                 _auth_script()]
    elif page == "cross":
        parts = [_script_with("report.html", "share-modal"),
                 _script_with("reports.html", "s3CloseMenus"),
                 _script_with("reports.html", "analysisConfirm"),
                 _auth_script()]
    else:  # pragma: no cover
        raise ValueError(page)
    return "\n".join(_neutralise(p) for p in parts)


# ---------------------------------------------------------------------------
# Node harness (faithful event semantics)
# ---------------------------------------------------------------------------

_HARNESS = r"""
'use strict';
class ClassList {
  constructor() { this.set = new Set(); }
  add(c) { this.set.add(c); }
  remove(c) { this.set.delete(c); }
  contains(c) { return this.set.has(c); }
  toggle(c) {}
}
const FETCH_CALLS = [];
const NATIVE_SUBMITS = [];
const REQUESTED_IDS = [];
class El {
  constructor(id) {
    this.id = id || ''; this.style = {}; this.textContent = '';
    this.value = ''; this.href = ''; this.dataset = {}; this.attrs = {};
    this.listeners = {}; this.checked = false; this.disabled = false;
    this.hidden = false; this.classList = new ClassList();
    this.children = []; this.className = '';
  }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  appendChild(c) { this.children.push(c); return c; }
  remove() {}
  select() {}
  click() {}
  closest(sel) { return null; }
  querySelector(sel) { return null; }
  querySelectorAll(sel) { return []; }
}
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
['ss-confirm','ss-confirm-text','ss-confirm-yes','ss-confirm-no',
 'extend-modal','extend-msg','extend-close',
 'share-modal','share-msg','share-link-row','share-link','share-mailto',
 'share-create','share-rotate','share-revoke','share-close','share-copy',
 'share-btn','analysis-modal','analysis-msg','analysis-confirm',
 'analysis-close','analysis-link-row','analysis-view',
 'premium-upsell-btn'].forEach(byId);
const docListeners = {};
function makeEvent(target) {
  return { target: target, defaultPrevented: false, _stop: false,
    _stopImm: false,
    preventDefault: function () { this.defaultPrevented = true; },
    stopPropagation: function () { this._stop = true; },
    stopImmediatePropagation: function () { this._stopImm = true; this._stop = true; } };
}
function dispatch(el, type, ev) {
  const list = (el.listeners[type] || []).slice();
  for (const fn of list) { fn(ev); if (ev._stopImm) { break; } }
  return ev;
}
function clickEl(el) {
  const ev = makeEvent(el);
  dispatch(el, 'click', ev);
  if (!ev._stop) {
    const dev = makeEvent(el);
    const list = (docListeners['click'] || []).slice();
    for (const fn of list) { fn(dev); if (dev._stopImm) { break; } }
  }
  return ev;
}
function dispatchSubmit(form) {
  const ev = makeEvent(form);
  dispatch(form, 'submit', ev);
  if (!ev.defaultPrevented) { NATIVE_SUBMITS.push(form.action); }
  return ev;
}
function clickSubmit(btn) { clickEl(btn); dispatchSubmit(btn._form); }
// My Reports dropdown structure (one row).
const menu = new El('menu'); menu.hidden = true;
const wrap = new El('wrap');
wrap.querySelector = function (sel) { return sel === '[data-s3-export-menu]' ? menu : null; };
const exportBtn = new El('export-btn');
exportBtn.setAttribute('aria-expanded', 'false');
exportBtn.closest = function (sel) { return sel === '.s3-export' ? wrap : null; };
function makeForm(action, inMenu) {
  const f = new El('form:' + action);
  f.action = action;
  f.setAttribute('data-confirm', 'Exports are free for this report.');
  const btn = new El('submit:' + action); btn.type = 'submit';
  if (inMenu) { btn.closest = function (sel) { return sel === '.s3-export' ? wrap : null; }; }
  f.querySelector = function (sel) { return sel === 'button[type="submit"]' ? btn : null; };
  f.requestSubmit = function () { dispatchSubmit(f); };
  f._btn = btn; btn._form = f;
  return f;
}
const reportForms = {
  pdf: makeForm('/reports/RID/pdf', false),
  csv: makeForm('/reports/RID/exports/csv', false),
  json: makeForm('/reports/RID/exports/json', false),
};
const ddForms = {
  pdf: makeForm('/reports/RID/pdf', false),
  csv: makeForm('/reports/RID/exports/csv', false),
  json: makeForm('/reports/RID/exports/json', false),
};
const myForms = {
  pdf: makeForm('/reports/RID/pdf', true),
  csv: makeForm('/reports/RID/exports/csv', true),
  json: makeForm('/reports/RID/exports/json', true),
};
const shareBtn = new El('share-open-btn');
shareBtn.setAttribute('data-report', 'RID');
shareBtn.setAttribute('data-formats', '');
shareBtn.setAttribute('data-create-key', 'ck');
shareBtn.setAttribute('data-rotate-key', 'rk');
shareBtn.setAttribute('data-revoke-key', 'vk');
shareBtn.setAttribute('data-active', '');
shareBtn.setAttribute('data-unlocked', '');
const analysisBtn = new El('analysis-open-btn');
analysisBtn.setAttribute('data-report', 'RID');
analysisBtn.setAttribute('data-eligible', '1');
analysisBtn.setAttribute('data-entitlement', '');
analysisBtn.setAttribute('data-deadline', '');
analysisBtn.setAttribute('data-reason', '');
const radios = ['txt','pdf','json','csv'].map(function (v) {
  const r = new El('radio-' + v); r.value = v; r.checked = (v === 'txt'); return r;
});
globalThis.window = globalThis;
globalThis.__productReady = true;
globalThis.location = { origin: 'https://example.test', assign: function () {} };
try { globalThis.URL.createObjectURL = function () { return 'blob:x'; };
      globalThis.URL.revokeObjectURL = function () {}; } catch (e) {}
globalThis.FormData = class {
  constructor(form) { this._form = form; this._map = {}; }
  append(k, v) { this._map[k] = v; }
  get(k) { return this._map[k] || null; }
};
globalThis.fetch = function (url, opts) {
  FETCH_CALLS.push(url);
  return Promise.resolve({ ok: true, status: 200,
    blob: function () { return Promise.resolve({}); },
    json: function () { return Promise.resolve({}); },
    headers: { get: function () { return 'attachment; filename="report.pdf"'; } } });
};
const PAGE = '__PAGE__';
function pageForms() {
  if (PAGE === 'report') { return [reportForms]; }
  if (PAGE === 'deepdive') { return [ddForms]; }
  if (PAGE === 'reports') { return [myForms]; }
  return [reportForms, myForms];  // cross
}
globalThis.document = {
  getElementById: function (id) { REQUESTED_IDS.push(id); return byId(id); },
  addEventListener: function (ev, fn) { (docListeners[ev] = docListeners[ev] || []).push(fn); },
  createElement: function (tag) { return new El('created-' + tag); },
  createTextNode: function (t) { const n = new El('text'); n.textContent = t; return n; },
  body: new El('body'),
  querySelectorAll: function (sel) {
    const sets = pageForms();
    const all = []; sets.forEach(function (s) { all.push(s.pdf, s.csv, s.json); });
    if (sel === 'form[data-confirm]') { return all; }
    if (sel === 'form[action$="/pdf"]') { return sets.map(function (s) { return s.pdf; }); }
    if (sel === 'form[data-auth-form]') { return []; }
    if (sel === 'form[data-retention-form]') { return []; }
    if (sel === '[data-s3-export-menu]') { return [menu]; }
    if (sel === '[data-s3-export-btn]') { return [exportBtn]; }
    if (sel === '.share-open') { return [shareBtn]; }
    if (sel === '.analysis-open') { return [analysisBtn]; }
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
async function flush() { for (let i = 0; i < 10; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
"""


def _run_js(page, scenario):
    full = (_HARNESS.replace("__PAGE__", page) + "\n" + _page_scripts(page)
            + "\n(async () => {\n  const out = {};\n" + scenario
            + "\n  out.fetchCalls = FETCH_CALLS.slice();\n"
            "  out.nativeSubmits = NATIVE_SUBMITS.slice();\n"
            "  out.requestedIds = REQUESTED_IDS.slice();\n"
            "  console.log('RESULT:' + JSON.stringify(out));\n"
            "})().catch(function (e) { console.error(e && e.stack || e); "
            "process.exit(3); });\n")
    proc = subprocess.run(["node", "-e", full], capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 0, \
        f"node harness failed:\n{proc.stdout}\n{proc.stderr}"
    line = next(l for l in proc.stdout.splitlines()
                if l.startswith("RESULT:"))
    return json.loads(line[len("RESULT:"):])


pytestmark_js = pytest.mark.skipif(
    shutil.which("node") is None, reason="node required for template JS tests")


# ---------------------------------------------------------------------------
# Tests 1-2: Report + Investigation Report pages — direct export, no modal
# ---------------------------------------------------------------------------

@pytestmark_js
def test_r7_1_report_page_exports_fire_directly_no_modal():
    out = _run_js("report", """
      clickSubmit(reportForms.pdf._btn); await flush();
      out.pdfFetch = FETCH_CALLS.length;
      out.pdfModal = byId('ss-confirm').style.display || '';
      clickSubmit(reportForms.csv._btn); await flush();
      clickSubmit(reportForms.json._btn); await flush();
      out.modalAfterAll = byId('ss-confirm').style.display || '';
      out.pdfBtnDisabled = reportForms.pdf._btn.disabled;
    """)
    # PDF intercepted exactly once by the auth fetch listener.
    assert out["pdfFetch"] == 1
    assert out["fetchCalls"] == ["/reports/RID/pdf"]
    # CSV/JSON submit natively, exactly once each.
    assert out["nativeSubmits"] == ["/reports/RID/exports/csv",
                                    "/reports/RID/exports/json"]
    # No confirmation modal at any step.
    assert out["pdfModal"] != "flex"
    assert out["modalAfterAll"] != "flex"
    # In-flight guard released after the PDF download completes.
    assert out["pdfBtnDisabled"] is False


@pytestmark_js
def test_r7_2_deep_dive_page_exports_fire_directly_no_modal():
    out = _run_js("deepdive", """
      clickSubmit(ddForms.pdf._btn); await flush();
      out.pdfFetch = FETCH_CALLS.length;
      out.pdfModal = byId('ss-confirm').style.display || '';
      clickSubmit(ddForms.csv._btn); await flush();
      clickSubmit(ddForms.json._btn); await flush();
      out.modalAfterAll = byId('ss-confirm').style.display || '';
    """)
    assert out["pdfFetch"] == 1
    assert out["fetchCalls"] == ["/reports/RID/pdf"]
    assert out["nativeSubmits"] == ["/reports/RID/exports/csv",
                                    "/reports/RID/exports/json"]
    assert out["pdfModal"] != "flex"
    assert out["modalAfterAll"] != "flex"


# ---------------------------------------------------------------------------
# Test 3: My Reports — dropdown exports fire directly, no modal (F1 chain;
# the F2 server-side regression is test_r7_f2_* below)
# ---------------------------------------------------------------------------

@pytestmark_js
def test_r7_3_my_reports_dropdown_exports_fire_directly_no_modal():
    out = _run_js("reports", """
      clickEl(exportBtn);
      out.menuOpen = !menu.hidden;
      clickSubmit(myForms.pdf._btn); await flush();
      out.pdfFetch = FETCH_CALLS.length;
      out.pdfModal = byId('ss-confirm').style.display || '';
      clickSubmit(myForms.csv._btn); await flush();
      clickSubmit(myForms.json._btn); await flush();
      out.modalAfterAll = byId('ss-confirm').style.display || '';
    """)
    assert out["menuOpen"] is True
    assert out["pdfFetch"] == 1
    assert out["fetchCalls"] == ["/reports/RID/pdf"]
    assert out["nativeSubmits"] == ["/reports/RID/exports/csv",
                                    "/reports/RID/exports/json"]
    assert out["pdfModal"] != "flex"
    assert out["modalAfterAll"] != "flex"


# ---------------------------------------------------------------------------
# Test 4: cross-control sequence — Report page then My Reports, and reverse;
# exactly one request per click, no stale confirmed/pending state
# ---------------------------------------------------------------------------

@pytestmark_js
def test_r7_4_cross_page_export_sequence_no_state_leak():
    out = _run_js("cross", """
      clickSubmit(reportForms.pdf._btn); await flush();
      out.afterReportFetch = FETCH_CALLS.length;
      clickEl(exportBtn);
      clickSubmit(myForms.pdf._btn); await flush();
      out.afterMyFetch = FETCH_CALLS.length;
      out.reportDataset = reportForms.pdf.dataset;
      out.myDataset = myForms.pdf.dataset;
      out.modal = byId('ss-confirm').style.display || '';
    """)
    assert out["afterReportFetch"] == 1
    assert out["afterMyFetch"] == 2
    assert out["fetchCalls"] == ["/reports/RID/pdf", "/reports/RID/pdf"]
    assert out["reportDataset"] == {}
    assert out["myDataset"] == {}
    assert out["modal"] != "flex"

    out = _run_js("cross", """
      clickEl(exportBtn);
      clickSubmit(myForms.pdf._btn); await flush();
      out.afterMyFetch = FETCH_CALLS.length;
      clickSubmit(reportForms.pdf._btn); await flush();
      out.afterReportFetch = FETCH_CALLS.length;
      out.reportDataset = reportForms.pdf.dataset;
      out.myDataset = myForms.pdf.dataset;
    """)
    assert out["afterMyFetch"] == 1
    assert out["afterReportFetch"] == 2
    assert out["reportDataset"] == {}
    assert out["myDataset"] == {}


# ---------------------------------------------------------------------------
# Test 5 (guard): neighbouring modals unaffected — passes on base and built
# ---------------------------------------------------------------------------

@pytestmark_js
def test_r7_5_guard_neighbouring_modals_unaffected():
    out = _run_js("report", """
      clickEl(byId('share-btn'));
      out.shareOpen = byId('share-modal').style.display || '';
      clickEl(byId('share-close'));
      out.shareClosed = byId('share-modal').style.display || '';
      clickEl(byId('premium-upsell-btn'));
      out.analysisOpen = byId('analysis-modal').style.display || '';
      clickEl(byId('analysis-close'));
      out.analysisClosed = byId('analysis-modal').style.display || '';
    """)
    assert out["shareOpen"] == "flex"
    assert out["shareClosed"] == "none"
    assert out["analysisOpen"] == "flex"
    assert out["analysisClosed"] == "none"

    out = _run_js("reports", """
      shareBtn.listeners.click.forEach(function (fn) { fn({}); });
      out.shareOpen = byId('share-modal').style.display || '';
      clickEl(byId('share-close'));
      out.shareClosed = byId('share-modal').style.display || '';
      clickEl(byId('extend-close'));
      out.extendClosed = byId('extend-modal').style.display || '';
    """)
    assert out["shareOpen"] == "flex"
    assert out["shareClosed"] == "none"
    assert out["extendClosed"] == "none"


# ---------------------------------------------------------------------------
# Test 7 (JS half): the reports.html IR dialog renders the approved promise
# ---------------------------------------------------------------------------

@pytestmark_js
def test_r7_7_reports_ir_dialog_uses_approved_promise():
    out = _run_js("reports", """
      analysisBtn.listeners.click.forEach(function (fn) { fn({}); });
      out.analysisMsg = byId('analysis-msg').textContent || '';
      out.analysisOpen = byId('analysis-modal').style.display || '';
    """)
    assert out["analysisOpen"] == "flex"
    assert APPROVED_PROMISE in out["analysisMsg"]
    assert OLD_PROMISE not in out["analysisMsg"]
    # Price / 90-day wording around the promise is preserved.
    assert out["analysisMsg"].startswith(
        "Investigation Report costs $9, paid by card at checkout. "
        "Exports and branding are included, and the report is kept "
        "for 90 days. ")


# ---------------------------------------------------------------------------
# Server-side tests (TestClient)
# ---------------------------------------------------------------------------

def _login_with_report(auth_env):
    from test_phase2b_reports_pdf import _create_result, _login, \
        _signup_and_verify
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, "release7.log")
    _login(auth_env, email)
    return rid


def test_r7_f1_rendered_pages_carry_no_confirm_markup(auth_env):
    """F1 markup premise on the real rendered pages (Report + My
    Reports): no data-confirm, no ss-confirm, no popup text."""
    rid = _login_with_report(auth_env)
    for path in (f"/reports/{rid}", "/reports"):
        page = auth_env.client.get(path)
        assert page.status_code == 200, (path, page.status_code)
        assert "data-confirm" not in page.text, path
        assert "ss-confirm" not in page.text, path
        assert "Exports are free for this report." not in page.text, path
    # deep_dive template source (rendering an IR needs a settled
    # purchase; the template is the surface of record for F1 here).
    dd = (_TEMPLATES / "deep_dive_report.html").read_text()
    assert 'data-confirm="' not in dd
    assert 'id="ss-confirm"' not in dd


def test_r7_6_guard_compare_card_under_batch_card(auth_env):
    """Test 6 (guard-shaped F3 pin): Compare card directly under the
    Batch card, element-for-element; Batch card byte-identical to
    base. Fails on base (no Compare card), passes built; the Batch
    half passes on both."""
    _login_with_report(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    batch_block = (
        '<a class="s3-entry-card" href="/batch" data-s3-entry="batch">\n'
        '    <span class="s3-entry-title">Batch analysis</span>\n'
        '    <span class="s3-entry-sub">Upload 2 to 5 log files and get '
        'one combined report, in upload order.</span>\n'
        '    <span class="s3-entry-link">Start a batch \u2192</span>\n'
        '  </a>')
    compare_block = (
        '<a class="s3-entry-card" href="/compare" '
        'data-s3-entry="compare">\n'
        '    <span class="s3-entry-title">Compare two logs</span>\n'
        '    <span class="s3-entry-sub">Upload two log files and see '
        'what changed between them.</span>\n'
        '    <span class="s3-entry-link">Start a compare \u2192</span>\n'
        '  </a>')
    assert batch_block in page.text
    assert compare_block in page.text
    # Directly under: nothing but whitespace between the two cards,
    # and both precede the pager/empty-state that follows them.
    between = page.text[page.text.index(batch_block) + len(batch_block):
                        page.text.index(compare_block)]
    assert between.strip() == ""
    # Same presentation classes (mobile: entry cards are block-level
    # anchors stacking full-width under the shared .s3-entry-card rule).
    assert page.text.count('class="s3-entry-card"') == 2


def test_r7_f2_stale_stored_pdf_regenerates(auth_env):
    """F2 regression (staging repro 2026-11-14): a completed PDF
    operation whose stored PDF result can no longer be validated
    (corrupt digest here; a missing cached file on staging) must NOT
    dead-end with the 410 'no longer available' error — the export
    regenerates from the still-valid source report and downloads.
    On base this returns 410; built it returns the regenerated PDF.
    The corrupt stored bytes must never be served."""
    from datetime import datetime, timedelta, timezone
    import base64 as b64
    from app import models
    from test_phase2b_reports_pdf import _create_result, _login, \
        _signup_and_verify
    email, user_id = _signup_and_verify(auth_env)
    rid = _create_result(auth_env, user_id, "stale-pdf.log")
    _login(auth_env, email)
    db = auth_env.sessions()
    try:
        manifest = json.dumps({
            "pdf_base64": b64.b64encode(b"fake-pdf").decode(),
            "filename": "stale-pdf.log"})
        pdf_result = models.Result(
            user_id=user_id, type="pdf",
            free_request_id=f"test-pdf-stale-{rid}",
            storage_manifest=manifest,
            integrity_digest="0" * 64,  # wrong digest: replay invalid
            byte_count=len(manifest.encode()),
            ready_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7))
        db.add(pdf_result)
        db.flush()
        db.add(models.Operation(
            user_id=user_id, type="pdf", status="completed",
            idempotency_key=f"pdf-{rid}", request_hash="dummy", cost=2,
            worker_id="worker-123",
            lease_expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=5),
            result_id=pdf_result.id))
        db.commit()
    finally:
        db.close()
    csrf = auth_env.client.get("/auth/csrf").json()["csrf_token"]
    auth_env.client.headers["X-CSRF-Token"] = csrf
    resp = auth_env.client.post(f"/reports/{rid}/pdf",
                                data={"csrf_token": csrf})
    assert resp.status_code == 200, resp.text[:300]
    assert resp.headers["content-type"].startswith("application/pdf")
    assert resp.content[:4] == b"%PDF"
    assert b"fake-pdf" not in resp.content


def test_r7_7_promise_constant_and_rendered_surfaces(auth_env):
    """Test 7 (server half): the constant IS the approved text, and
    the pricing promise element + paid-consent promise elements
    render it exactly (the surrounding prose on pricing.html is a
    separate copy block, out of F4 scope — assertions target the
    promise elements themselves)."""
    from app import stripe_billing as sb
    assert sb.PAY_NOW_PROMISE == APPROVED_PROMISE
    page = auth_env.client.get("/credits")
    assert page.status_code == 200
    m = re.search(r'id="pay-now-promise">([^<]+)<', page.text)
    assert m is not None
    # Jinja HTML-escapes the apostrophes (&#39;); browsers render the
    # approved text verbatim, so compare after unescaping.
    assert html.unescape(m.group(1)) == APPROVED_PROMISE
    # Template pin: both paid_consent variants render the shared
    # {{ promise }} context var; no hard-coded old promise remains
    # in the template.
    consent = (_TEMPLATES / "paid_consent.html").read_text()
    assert consent.count("{{ promise }}") == 2
    assert OLD_PROMISE not in consent


def test_r7_7b_part_b_blocks_render_approved_promise(auth_env,
                                                     monkeypatch):
    """Test 7 extension (Remediation 1, Part B — Sunny disposition
    on the F4 residue): the purchase-decision blocks the original
    spec did NOT name carry the approved promise verbatim as a
    segment replacement — report.html's IR dialog paragraph and
    premium-card paragraph, and pricing.html's promise-bearing
    blocks (Failure-never-consumes policy, IR FAQ paragraph,
    failed-generation FAQ, refund FAQ). Surrounding prose, prices
    and suffixes are preserved; the old promise segments are gone
    from these blocks. NOT pinned here (named follow-up, out of
    scope): terms.html / support.html prose, the entitlement-held
    variants, and the main.py error string."""
    old_report_segment = (
        "Payment is captured at checkout; if generation fails, your "
        "purchase is never consumed \u2014 you can retry. A purchase "
        "that can never be redeemed is refundable on request via "
        "disputes@goodfolkdigital.com.")
    # --- report.html: exactly two $9 purchase paragraphs, both
    # re-pinned (IR dialog + premium card).
    report_src = (_TEMPLATES / "report.html").read_text()
    paras = re.findall(
        r"<p[^>]*>(Investigation Report costs \$9, paid by card at "
        r"checkout\. .*?)</p>", report_src, re.S)
    assert len(paras) == 2, paras
    for para in paras:
        assert APPROVED_PROMISE in para
        assert old_report_segment not in para
        assert para.startswith(
            "Investigation Report costs $9, paid by card at "
            "checkout. Exports and branding are included, and the "
            "report is kept for 90 days. ")
    # --- pricing.html source blocks.
    pricing_src = (_TEMPLATES / "pricing.html").read_text()

    def _block_after(marker):
        i = pricing_src.index(marker)
        return pricing_src[i:pricing_src.index("</p>", i)] \
            if "</p>" in pricing_src[i:] else pricing_src[i:]

    policy = pricing_src[
        pricing_src.index("<strong>Failure never consumes</strong>"):
        pricing_src.index("</div>", pricing_src.index(
            "<strong>Failure never consumes</strong>"))]
    assert APPROVED_PROMISE in policy
    assert "never consumed" not in policy
    ir_faq = _block_after(
        "<h3>What does the Investigation Report include?</h3>")
    assert APPROVED_PROMISE in ir_faq
    assert "It costs $9 per report, paid by card at checkout." in ir_faq
    assert "the report is kept for 90 days." in ir_faq
    assert '<a href="/sample-report">' in ir_faq
    fail_faq = _block_after(
        "<h3>What happens if my analysis fails?</h3>")
    assert APPROVED_PROMISE in fail_faq
    assert fail_faq.startswith(
        "<h3>What happens if my analysis fails?</h3>\n"
        "    <p>You are never charged for a failed generation. ")
    refund_faq = _block_after("<h3>Can I get a refund?</h3>")
    assert APPROVED_PROMISE in refund_faq
    assert ("Otherwise, per-report purchases are final, subject to "
            "applicable legal obligations.") in refund_faq
    for block in (ir_faq, fail_faq, refund_faq):
        assert "Payment is captured at checkout" not in block
        assert "refundable on request" not in block
    # --- Rendered pricing page: the promise element plus the four
    # blocks render the approved text (5 occurrences after
    # unescaping the element's rendered apostrophes).
    page = auth_env.client.get("/credits")
    assert page.status_code == 200
    assert html.unescape(page.text).count(APPROVED_PROMISE) == 5
    # Rendered report page: both $9 purchase paragraphs render ONLY
    # in the not-yet-purchased, product-ready state — with the
    # Investigation Report Price env unset, product_ready is false
    # and both blocks render the fail-closed "Coming soon" variant
    # instead (verified: approved-promise count 0 without the env,
    # exactly 2 with it). Aim the rendered half at the purchase
    # state by configuring the Price, like the Phase A/B/C fixtures.
    monkeypatch.setenv("STRIPE_PRICE_INVESTIGATION_REPORT",
                       "price_r7_7b_test")
    # Rendered report page (owned report): both purchase paragraphs
    # carry the approved promise; the old segment is absent.
    rid = _login_with_report(auth_env)
    rpage = auth_env.client.get(f"/reports/{rid}")
    assert rpage.status_code == 200
    assert html.unescape(rpage.text).count(APPROVED_PROMISE) >= 2
    assert old_report_segment not in rpage.text


def test_r7_7_paid_consent_pages_render_approved_promise(p164b_env):
    """Test 7 (consent routes): the Compare and Batch 402 consent
    pages render the approved promise in their promise element(s)."""
    import test_issue164_phase_b as pb
    env = p164b_env
    _, _uid, _csrf = pb._make_user(env)
    for post, files in ((pb._post_compare, None),
                        (pb._post_batch, pb._batch_files())):
        r = post(env, files) if files is not None else post(env)
        assert r.status_code == 402, r.text[:300]
        bodies = re.findall(
            r'id="product-checkout-promise">([^<]+)<', r.text)
        assert bodies, "no promise element rendered"
        for body in bodies:
            assert html.unescape(body) == APPROVED_PROMISE
        assert OLD_PROMISE not in r.text
