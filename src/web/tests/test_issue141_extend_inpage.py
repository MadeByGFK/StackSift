"""Issue #141: Extend on My Reports navigated to raw JSON.

Bug: in ``reports.html`` the Extend form carries ``data-confirm``,
and the shared confirm handler re-submits the form natively on Yes
(``confirmedForm.requestSubmit()``). Export forms are unaffected
(their responses are file downloads), but
``POST /reports/{id}/retention`` returns a JSON document
(``{"status":"extended",...,"cost":1}``), so the browser navigated
to the raw JSON page and stranded the user.

Fix (``reports.html`` only; no route, pricing, cap, or key changes):

- The Extend form is marked ``data-retention-form`` and a dedicated
  submit listener — registered AFTER the data-confirm handler, which
  stopImmediatePropagation()s the unconfirmed submit, mirroring the
  PDF fetch pattern in ``auth_form_script.html`` — runs only on the
  confirmed resubmit, preventDefault()s it, and posts the SAME form
  fields (CSRF token + hidden ``idempotency_key``, unchanged) via
  fetch.
- Success: the affected row updates in place (expiry date +
  "Expires in N days" pill), the header credit badge (#credit-badge)
  drops by the charged cost, and a per-row "Retention extended."
  status shows. A ``replayed`` response updates the row and — PR
  #143 remediation (verified Codex P2) — refreshes the badge from
  the authoritative ``GET /auth/balance`` payload instead of
  leaving it untouched: a replay means an earlier attempt may
  have committed the charge while its response was lost (network
  error → error modal, badge unchanged), so the local badge can
  be one credit too high until reload. A fresh (non-replayed)
  success still decrements locally; a failed/unusable balance
  refresh leaves the badge unchanged and shows no error (the
  extension itself succeeded).
- Failure (402 insufficient credits, 409 cap, network error): the
  server error shows in the in-page #extend-modal; no navigation,
  no row change, no balance change.
- The data-confirm popup, its exact wording, and Cancel semantics
  are unchanged; deep_dive (Analysis Report) rows still have no
  Extend form (#106 Stage 2 guard).

TEETH: the page-structure test and every Node harness test below
fail on the pre-fix tree (9bc372f) and pass on the built tree —
verified by copying this file into a pristine checkout of 9bc372f
and running it there (see the build report). The deep_dive
suppression test passes on both trees BY DESIGN — it guards the
#106 Stage 2 decision this fix must not disturb.

PR #143 REMEDIATION TEETH: the new lost-response test (e) fails
against the pre-remediation template (PR head d784241c / local
c759ded, where a replayed response returned early and never
refreshed the badge) and passes with the remediation — verified
by swapping in ``git show HEAD:.../reports.html`` for that run
(see the remediation report).
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from app import main

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import _setup
from test_deep_dive_paid import _generate

_TEMPLATES = Path(main.__file__).parent / "templates"

_CONFIRM_TEXT = "Extend this report's retention by 90 days for 1 credit?"


# --- page structure -----------------------------------------------------------

def _extend_form_slice(html, rid):
    start = html.index(f'action="/reports/{rid}/retention"')
    start = html.rindex("<form", 0, start)
    end = html.index("</form>", start)
    return html[start:end]


def test_reports_page_extend_form_is_fetch_handled_in_page(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    text = page.text
    form = _extend_form_slice(text, rid)
    # The confirmation popup and its exact wording are unchanged,
    # and the form still carries the CSRF token + idempotency key
    # the fetch path must send.
    assert f'data-confirm="{_CONFIRM_TEXT}"' in form
    assert 'name="csrf_token"' in form
    assert 'name="idempotency_key"' in form
    # The fix markers: the form is fetch-handled, the row carries
    # updatable expiry/status elements, and the in-page error modal
    # exists.
    assert "data-retention-form" in form
    assert "data-retention-expiry-date" in text
    assert "data-retention-expiry-pill" in text
    assert "data-retention-status" in text
    assert 'id="extend-modal"' in text
    assert 'id="extend-msg"' in text


def test_reports_page_deep_dive_rows_still_have_no_extend(auth_env):
    # Guard (passes on both trees by design): the #106 Stage 2
    # suppression of Extend on Analysis Report rows is untouched.
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    analysis_id = gen.json()["analysis_result_id"]
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    cards = page.text.split('<li class="card">')

    def _card_for(report_id):
        view_link = f'href="/reports/{report_id}" class="btn btn-ghost">View'
        matches = [c for c in cards if view_link in c]
        assert len(matches) == 1, report_id
        return matches[0]

    deep = _card_for(str(analysis_id))
    assert "Extend" not in deep
    assert f"/reports/{analysis_id}/retention" not in deep
    normal = _card_for(str(rid))
    assert f"/reports/{rid}/retention" in normal and ">Extend</button>" in normal


# --- Node harness: the real reports.html inline script, driven as a user -----

pytestmark_js = pytest.mark.skipif(
    shutil.which("node") is None, reason="node required for template JS tests")

_HARNESS = r"""
'use strict';
class ClassList {
  constructor() { this.set = new Set(); }
  add(c) { this.set.add(c); }
  remove(c) { this.set.delete(c); }
  contains(c) { return this.set.has(c); }
}
class El {
  constructor(id) {
    this.id = id || ''; this.style = {}; this.textContent = '';
    this.value = ''; this.href = ''; this.dataset = {};
    this.attrs = {}; this.listeners = {}; this.checked = false;
    this.disabled = false; this.classList = new ClassList();
  }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  select() {}
  appendChild() {}
  remove() {}
  click() {}
}
// Fixed clock: 2026-11-04T12:00:00Z. The fetch stub's success expiry
// (2027-02-09T12:00:00Z) is then exactly 97 days out, so the pill
// text is deterministic.
Date.now = function () { return Date.parse('2026-11-04T12:00:00Z'); };
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
['ss-confirm','ss-confirm-text','ss-confirm-yes','ss-confirm-no',
 'share-modal','share-msg','share-link-row','share-link','share-mailto',
 'share-create','share-rotate','share-revoke','share-close','share-copy',
 'analysis-modal','analysis-msg','analysis-confirm','analysis-close',
 'analysis-link-row','analysis-view','extend-modal','extend-msg',
 'extend-close'].forEach(byId);
const badge = byId('credit-badge');
badge.textContent = '\u{1FA99} 3 credits';
const radios = ['txt','pdf','json','csv'].map(function (v) {
  const r = new El('radio-' + v); r.value = v; r.name = 'share-format'; return r;
});
radios[0].checked = true;
// The affected row: expiry date span, expiry pill, status element.
const dateEl = new El('date'); dateEl.textContent = 'Expires 2026-11-11';
const pillEl = new El('pill'); pillEl.textContent = 'Expires in 7 days';
const statusEl = new El('status'); statusEl.style.display = 'none';
const cardEl = new El('card');
cardEl.querySelector = function (sel) {
  if (sel === '[data-retention-expiry-date]') { return dateEl; }
  if (sel === '[data-retention-expiry-pill]') { return pillEl; }
  if (sel === '[data-retention-status]') { return statusEl; }
  return null;
};
// The Extend form and its submit button.
const extendBtn = { disabled: false };
let nativeSubmits = 0;
const retForm = new El('ret-form');
retForm.action = '/reports/RID/retention';
retForm._fields = { csrf_token: 'csrf-test', idempotency_key: 'ret-key-123' };
retForm.getAttribute = function (k) {
  if (k === 'data-confirm') {
    return "Extend this report's retention by 90 days for 1 credit?";
  }
  return El.prototype.getAttribute.call(this, k);
};
retForm.querySelector = function (sel) {
  return sel.indexOf('submit') !== -1 ? extendBtn : null;
};
retForm.closest = function () { return cardEl; };
function dispatchSubmit(form) {
  const ev = {
    defaultPrevented: false, _stop: false,
    preventDefault: function () { this.defaultPrevented = true; },
    stopImmediatePropagation: function () { this._stop = true; },
  };
  const handlers = (form.listeners.submit || []).slice();
  for (const fn of handlers) { fn(ev); if (ev._stop) { break; } }
  return ev;
}
retForm.requestSubmit = function () {
  // A native submission happens iff no handler preventDefault()s
  // the (re)submit — that navigation is exactly the #141 bug.
  const ev = dispatchSubmit(retForm);
  if (!ev.defaultPrevented) { nativeSubmits++; }
};
globalThis.window = globalThis;
globalThis.location = { origin: 'https://example.test' };
globalThis.navigator = {};
globalThis.FormData = class {
  constructor(form) {
    this._map = {};
    if (form && form._fields) {
      for (const k of Object.keys(form._fields)) { this._map[k] = form._fields[k]; }
    }
  }
  append(k, v) { this._map[k] = v; }
  get(k) { return Object.prototype.hasOwnProperty.call(this._map, k) ? this._map[k] : null; }
};
globalThis.document = {
  getElementById: byId,
  createElement: function () { return new El('created'); },
  createTextNode: function (t) { return { textContent: t }; },
  body: new El('body'),
  addEventListener: function () {},
  querySelectorAll: function (sel) {
    if (sel === 'form[data-confirm]') { return [retForm]; }
    if (sel === 'form[data-retention-form]') { return [retForm]; }
    if (sel === 'input[name="share-format"]') { return radios; }
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
let fetchMode = 'ok';
const fetchCalls = [];
const retentionCalls = [];
const balanceCalls = [];
globalThis.fetch = function (url, opts) {
  const body = opts && opts.body;
  const call = {
    url: String(url),
    method: opts && opts.method,
    credentials: opts && opts.credentials,
    csrf: body && body.get ? body.get('csrf_token') : null,
    key: body && body.get ? body.get('idempotency_key') : null,
  };
  fetchCalls.push(call);
  // Route by URL (PR #143 remediation): the badge refresh reads
  // the authoritative balance. The badge starts at 3 credits and
  // exactly one charge has committed in every scenario below, so
  // the authoritative balance is always 2 here.
  if (String(url) === '/auth/balance' || String(url).indexOf('/auth/balance') !== -1) {
    balanceCalls.push(call);
    return Promise.resolve({
      ok: true, status: 200,
      json: function () { return Promise.resolve({ balance: 2 }); },
    });
  }
  retentionCalls.push(call);
  if (fetchMode === 'error') {
    return Promise.resolve({
      ok: false, status: 402,
      json: function () {
        return Promise.resolve({
          error: 'Retention extension costs 1 credit. Insufficient eligible credits.',
          purchase_url: '/credits',
        });
      },
    });
  }
  if (fetchMode === 'network') { return Promise.reject(new Error('down')); }
  const replayed = fetchMode === 'replayed'
    || (fetchMode === 'ok-replay-second' && retentionCalls.length > 1);
  return Promise.resolve({
    ok: true, status: 200,
    json: function () {
      return Promise.resolve({
        status: 'extended', result_id: 'RID',
        expires_at: '2027-02-09T12:00:00+00:00', cost: 1,
        replayed: replayed,
      });
    },
  });
};
async function flush() { for (let i = 0; i < 10; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
async function click(el) {
  (el.listeners.click || []).forEach(function (fn) {
    fn({ preventDefault: function () {}, stopImmediatePropagation: function () {} });
  });
  await flush();
}
async function submitAndConfirm() {
  dispatchSubmit(retForm);
  await click(byId('ss-confirm-yes'));
}
function snap() {
  return {
    fetchCount: fetchCalls.length,
    retentionCount: retentionCalls.length,
    retentionCalls: retentionCalls,
    balanceCount: balanceCalls.length,
    balanceCalls: balanceCalls,
    nativeSubmits: nativeSubmits,
    confirmDisplay: byId('ss-confirm').style.display || '',
    confirmText: byId('ss-confirm-text').textContent || '',
    dateText: dateEl.textContent || '',
    pillText: pillEl.textContent || '',
    statusText: statusEl.textContent || '',
    statusDisplay: statusEl.style.display || '',
    badgeText: badge.textContent || '',
    extendDisplay: byId('extend-modal').style.display || '',
    extendMsg: byId('extend-msg').textContent || '',
    btnDisabled: !!extendBtn.disabled,
    calls: fetchCalls,
  };
}
"""


def _run_js(scenario):
    html = (_TEMPLATES / "reports.html").read_text()
    script = None
    for candidate in re.findall(r"<script>(.*?)</script>", html, re.S):
        if "data-confirm" in candidate:
            script = candidate
            break
    assert script is not None, "reports.html inline script not found"
    script = script.replace("{{ csrf_token }}", "csrf-test")
    script = script.replace("{{ analysis_report_cost }}", "3")
    full = (_HARNESS + "\n" + script + "\n(async () => {\n  const out = {};\n"
            + scenario + "\n  console.log('RESULT:' + JSON.stringify(out));\n"
            "})().catch(function (e) { console.error(e && e.stack || e); process.exit(3); });\n")
    proc = subprocess.run(["node", "-e", full], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"node harness failed:\n{proc.stdout}\n{proc.stderr}"
    line = next(l for l in proc.stdout.splitlines() if l.startswith("RESULT:"))
    return json.loads(line[len("RESULT:"):])


@pytestmark_js
def test_a_confirmed_extend_fetches_without_navigation_and_cancel_is_noop():
    out = _run_js("""
      dispatchSubmit(retForm);
      out.afterFirst = snap();
      await click(byId('ss-confirm-no'));
      out.afterCancel = snap();
      await submitAndConfirm();
      out.afterYes = snap();
    """)
    # Initial click: popup only, exact wording, nothing sent.
    assert out["afterFirst"]["confirmDisplay"] == "flex", out
    assert out["afterFirst"]["confirmText"] == (
        "Extend this report's retention by 90 days for 1 credit?")
    assert out["afterFirst"]["fetchCount"] == 0
    assert out["afterFirst"]["nativeSubmits"] == 0
    # Cancel: no fetch, no native submit, popup closed.
    assert out["afterCancel"]["fetchCount"] == 0, out
    assert out["afterCancel"]["nativeSubmits"] == 0, out
    assert out["afterCancel"]["confirmDisplay"] == "none", out
    # Yes: exactly one fetch to the retention endpoint carrying the
    # form's own CSRF token + idempotency key, and NO native submit
    # (no navigation to the raw JSON response).
    after = out["afterYes"]
    assert after["fetchCount"] == 1, after
    assert after["nativeSubmits"] == 0, after
    call = after["calls"][0]
    assert call["url"].endswith("/reports/RID/retention"), call
    assert call["method"] == "POST", call
    assert call["csrf"] == "csrf-test", call
    assert call["key"] == "ret-key-123", call


@pytestmark_js
def test_b_success_updates_row_expiry_and_header_balance_in_place():
    out = _run_js("""
      await submitAndConfirm();
      out.after = snap();
    """)
    after = out["after"]
    assert after["nativeSubmits"] == 0, after
    assert after["dateText"] == "Expires 2027-02-09", after
    assert after["pillText"] == "Expires in 97 days", after
    assert after["badgeText"] == "\U0001FA99 2 credits", after
    assert after["statusText"] == "Retention extended.", after
    assert after["statusDisplay"] == "", after
    assert after["extendDisplay"] != "flex", after  # no error modal
    assert after["btnDisabled"] is False, after


@pytestmark_js
def test_c_failure_shows_in_page_error_with_no_navigation_or_change():
    out = _run_js("""
      fetchMode = 'error';
      await submitAndConfirm();
      out.afterError = snap();
      fetchMode = 'network';
      await submitAndConfirm();
      out.afterNetwork = snap();
    """)
    for snap_out in (out["afterError"], out["afterNetwork"]):
        assert snap_out["nativeSubmits"] == 0, snap_out
        assert snap_out["extendDisplay"] == "flex", snap_out
        assert snap_out["dateText"] == "Expires 2026-11-11", snap_out
        assert snap_out["pillText"] == "Expires in 7 days", snap_out
        assert snap_out["badgeText"] == "\U0001FA99 3 credits", snap_out
        assert snap_out["btnDisabled"] is False, snap_out
    assert "Insufficient eligible credits" in out["afterError"]["extendMsg"]
    assert out["afterNetwork"]["extendMsg"] == (
        "Retention extension failed. Please try again.")


@pytestmark_js
def test_d_retry_sends_same_idempotency_key_and_charges_once():
    out = _run_js("""
      fetchMode = 'ok-replay-second';
      await submitAndConfirm();
      out.afterFirst = snap();
      await submitAndConfirm();
      out.afterRetry = snap();
    """)
    retry = out["afterRetry"]
    # Count RETENTION calls specifically (PR #143 remediation):
    # the replayed second response now also fetches /auth/balance
    # to refresh the badge, so the total fetch count is higher.
    assert retry["retentionCount"] == 2, retry
    assert retry["nativeSubmits"] == 0, retry
    keys = [c["key"] for c in retry["retentionCalls"]]
    assert keys == ["ret-key-123", "ret-key-123"], keys
    # Exactly one credit was charged across both submits: the
    # replayed response refreshes the badge from /auth/balance
    # (balance: 2), it does not decrement a second time.
    assert retry["badgeText"] == "\U0001FA99 2 credits", retry
    assert retry["dateText"] == "Expires 2027-02-09", retry
    assert retry["pillText"] == "Expires in 97 days", retry


@pytestmark_js
def test_e_lost_response_retry_replayed_refreshes_badge_from_balance():
    # PR #143 remediation regression (verified Codex P2): the
    # server commits the extension on the first attempt but the
    # response is lost (network error -> error modal, badge
    # unchanged). The retry re-sends the SAME idempotency key and
    # the server replays the recorded outcome
    # ({status:'extended', replayed:true, cost:1, ...}): the row
    # updates to success AND the badge must become the
    # authoritative balance (2), not stay at 3 until reload.
    out = _run_js("""
      fetchMode = 'network';
      await submitAndConfirm();
      out.afterNetwork = snap();
      fetchMode = 'replayed';
      await submitAndConfirm();
      out.afterRetry = snap();
    """)
    lost = out["afterNetwork"]
    assert lost["nativeSubmits"] == 0, lost
    assert lost["extendDisplay"] == "flex", lost
    assert lost["extendMsg"] == (
        "Retention extension failed. Please try again."), lost
    assert lost["badgeText"] == "\U0001FA99 3 credits", lost
    assert lost["dateText"] == "Expires 2026-11-11", lost
    assert lost["pillText"] == "Expires in 7 days", lost
    assert lost["balanceCount"] == 0, lost

    retry = out["afterRetry"]
    assert retry["nativeSubmits"] == 0, retry
    assert retry["retentionCount"] == 2, retry
    keys = [c["key"] for c in retry["retentionCalls"]]
    assert keys == ["ret-key-123", "ret-key-123"], keys
    # Row updates to success on the replayed response.
    assert retry["dateText"] == "Expires 2027-02-09", retry
    assert retry["pillText"] == "Expires in 97 days", retry
    assert retry["statusText"] == "Retention extended.", retry
    # Badge is refreshed from GET /auth/balance (same-origin),
    # exactly once, to the authoritative balance.
    assert retry["balanceCount"] == 1, retry
    balance_call = retry["balanceCalls"][0]
    assert balance_call["url"] == "/auth/balance", balance_call
    assert balance_call["credentials"] == "same-origin", balance_call
    assert retry["badgeText"] == "\U0001FA99 2 credits", retry
    assert retry["btnDisabled"] is False, retry
