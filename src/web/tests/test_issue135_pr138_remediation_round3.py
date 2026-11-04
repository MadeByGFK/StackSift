"""Issue #135 / PR #138 remediation round 3: one Codex P2 finding.

Round 3 finding (Codex re-review on head f3853977, finding 7): the
share popups checked the selected format when a request STARTED
but not when its response ARRIVED. If a user started creating (or
rotating) a TXT link and selected CSV before the request
completed, the format-change handler cleared the link row — but
the eventual response then called ``showLink`` unconditionally and
displayed the TXT URL under the CSV selection (and set the
Create/Rotate/Revoke buttons for the captured format). The round 2
tests only switched formats after awaiting completion, so this
race was uncovered.

Fix: in both popups (report page ``report.html`` and My Reports
``reports.html``), the create, rotate, and revoke handlers still
apply their per-row / per-format state updates for the CAPTURED
format (fresh idempotency key, add/remove of the captured format
from the active set), but the popup DISPLAY writes are guarded
against the format selected at response time. The returned URL is
shown only when the captured format still equals
``selectedShareFormat()``; when it differs, the stale URL is not
displayed and the buttons/message are refreshed from the current
selection via ``refreshShareButtonsForSelectedFormat()``.

Harness: following round 2's template-JS tests, these tests
extract the actual inline share script from each template, run it
in Node against a minimal DOM stub, and drive it as a user would —
except that the fetch stub is DEFERRED: each fetch returns a
promise the scenario resolves manually, so a format switch can be
interleaved between the click and the response, exactly as in the
finding. The fetch stub returns a distinct ``/s/TOKEN-<FORMAT>``
URL per format. No server behaviour is exercised here.

TEETH: the deferred-switch tests (create, rotate, revoke) fail on
the pre-fix tree (a8d4647) and pass on the fixed tree — verified by
stashing the template changes and re-running this file. The
no-switch control test passes on BOTH trees by design: it pins the
unchanged behaviour when no race occurs, so it is a control, not
teeth.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from app import main

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="node required for template JS tests")

_TEMPLATES = Path(main.__file__).parent / "templates"

_HARNESS = r"""
'use strict';
class El {
  constructor(id) {
    this.id = id || ''; this.style = {}; this.textContent = '';
    this.value = ''; this.href = ''; this.dataset = {};
    this.attrs = {}; this.listeners = {}; this.checked = false;
  }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  select() {}
  requestSubmit() {}
}
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
['export-btn','export-dropdown','ss-confirm','ss-confirm-text','ss-confirm-yes',
 'ss-confirm-no','share-modal','share-msg','share-link-row','share-link',
 'share-mailto','share-create','share-rotate','share-revoke','share-close',
 'share-btn','share-copy'].forEach(byId);
const radios = ['txt','pdf','json','csv'].map(function (v) {
  const r = new El('radio-' + v); r.value = v; r.name = 'share-format'; return r;
});
radios[0].checked = true;
const lockNotes = [new El('lock-1'), new El('lock-2'), new El('lock-3')];
const rowBtns = [];
globalThis.window = globalThis;
globalThis.location = { origin: 'https://example.test' };
globalThis.document = {
  getElementById: byId,
  querySelectorAll: function (sel) {
    if (sel === 'input[name="share-format"]') { return radios; }
    if (sel === '.share-open') { return rowBtns; }
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
// DEFERRED fetch: each call captures its resolver; the scenario
// resolves it manually via resolveFetch() AFTER interleaving a
// format switch, reproducing the round 3 race.
let pendingFetchResolve = null;
globalThis.fetch = function (path, opts) {
  const fmt = opts && opts.body && opts.body.get ? opts.body.get('format') : 'txt';
  let body;
  if (path.indexOf('/revoke') !== -1) { body = { status: 'revoked' }; }
  else { body = { share_url: '/s/TOKEN-' + String(fmt).toUpperCase() }; }
  return new Promise(function (resolve) {
    pendingFetchResolve = function () {
      resolve({
        ok: true, status: 200,
        json: function () { return Promise.resolve(body); },
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
function changeTo(fmt) {
  radios.forEach(function (r) { r.checked = (r.value === fmt); });
  const r = radios.find(function (x) { return x.value === fmt; });
  (r.listeners.change || []).forEach(function (fn) { fn({}); });
}
function snap() {
  const row = byId('share-link-row'); const box = byId('share-link');
  return { display: row.style.display || '', value: box.value || '',
           mailto: byId('share-mailto').href || '',
           msg: byId('share-msg').textContent || '',
           create: byId('share-create').style.display || '',
           rotate: byId('share-rotate').style.display || '',
           revoke: byId('share-revoke').style.display || '' };
}
"""

_SCENARIO_TAIL = r"""
  console.log('RESULT:' + JSON.stringify(out));
})().catch(function (e) { console.error(e && e.stack || e); process.exit(3); });
"""


def _extract_script(template_name):
    html = (_TEMPLATES / template_name).read_text()
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    for script in scripts:
        if "refreshShareButtonsForSelectedFormat" in script:
            return script
    raise AssertionError(f"share script not found in {template_name}")


def _run(template_name, scenario, *, active_formats=()):
    script = _extract_script(template_name)
    script = script.replace("{{ share_create_key }}", "create-key")
    script = script.replace("{{ share_rotate_key }}", "rotate-key")
    script = script.replace("{{ share_revoke_key }}", "revoke-key")
    script = script.replace("{{ csrf_token }}", "csrf-test")
    script = script.replace("{{ report_id }}", "RID")
    # report.html renders the per-format active set from the server;
    # substitute the scenario's set.
    script = re.sub(
        r"var shareActiveFormats = .*?;",
        "var shareActiveFormats = " + json.dumps(list(active_formats)) + ";",
        script, count=1, flags=re.S)
    setup = ""
    if template_name == "reports.html":
        formats = ",".join(active_formats)
        setup = (
            "const rowBtn = new El('row-1');\n"
            "rowBtn.setAttribute('data-report', 'RID');\n"
            "rowBtn.setAttribute('data-create-key', 'create-key');\n"
            "rowBtn.setAttribute('data-rotate-key', 'rotate-key');\n"
            "rowBtn.setAttribute('data-revoke-key', 'revoke-key');\n"
            f"rowBtn.setAttribute('data-formats', '{formats}');\n"
            f"rowBtn.setAttribute('data-active', '{'1' if active_formats else ''}');\n"
            "rowBtn.setAttribute('data-unlocked', '1');\n"
            "rowBtns.push(rowBtn);\n")
    full = (_HARNESS + "\n" + setup + "\n" + script + "\n"
            "(async () => {\n  const out = {};\n" + scenario
            + _SCENARIO_TAIL)
    proc = subprocess.run(
        ["node", "-e", full], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, (
        f"node harness failed for {template_name}:\n{proc.stdout}\n{proc.stderr}")
    line = next(l for l in proc.stdout.splitlines() if l.startswith("RESULT:"))
    return json.loads(line[len("RESULT:"):])


_OPEN = {
    "report.html": "await click(byId('share-btn'));\n",
    "reports.html": "await click(rowBtns[0]);\n",
}


@pytest.mark.parametrize("template", ["report.html", "reports.html"])
def test_create_response_after_format_switch_does_not_display_stale_url(template):
    # No format is active yet: after the switch, CSV's own state is
    # "no link" — Create visible, Rotate/Revoke hidden, no message.
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-create'));
      changeTo('csv');
      out.afterSwitch = snap();
      await resolveFetch();
      out.afterResolve = snap();
      changeTo('txt');
      out.afterSwitchBack = snap();
    """, active_formats=())
    # The stale TXT URL must NOT be displayed under the CSV
    # selection: row hidden, input empty, mailto cleared.
    assert out["afterResolve"]["display"] == "none", out["afterResolve"]
    assert out["afterResolve"]["value"] == "", out["afterResolve"]
    assert "TOKEN-TXT" not in out["afterResolve"]["mailto"]
    # Buttons and message reflect CSV's (inactive) state, not the
    # captured TXT create's success state.
    assert out["afterResolve"]["create"] == "", out["afterResolve"]
    assert out["afterResolve"]["rotate"] == "none", out["afterResolve"]
    assert out["afterResolve"]["revoke"] == "none", out["afterResolve"]
    assert out["afterResolve"]["msg"] == "", out["afterResolve"]
    # The per-format state update for the CAPTURED format still
    # applied: switching back to TXT shows TXT as active (Rotate /
    # Revoke offered), even though its URL was never displayed.
    assert out["afterSwitchBack"]["create"] == "none", out["afterSwitchBack"]
    assert out["afterSwitchBack"]["rotate"] == "", out["afterSwitchBack"]
    assert out["afterSwitchBack"]["revoke"] == "", out["afterSwitchBack"]
    assert out["afterSwitchBack"]["display"] == "none", out["afterSwitchBack"]
    assert out["afterSwitchBack"]["value"] == "", out["afterSwitchBack"]


@pytest.mark.parametrize("template", ["report.html", "reports.html"])
def test_rotate_response_after_format_switch_does_not_display_stale_url(template):
    # TXT is active (Rotate is offered for it); CSV is not.
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-rotate'));
      changeTo('csv');
      out.afterSwitch = snap();
      await resolveFetch();
      out.afterResolve = snap();
    """, active_formats=("txt",))
    assert out["afterResolve"]["display"] == "none", out["afterResolve"]
    assert out["afterResolve"]["value"] == "", out["afterResolve"]
    assert "TOKEN-TXT" not in out["afterResolve"]["mailto"]
    # Buttons and message reflect CSV's (inactive) state, not the
    # captured TXT rotate's success state.
    assert out["afterResolve"]["create"] == "", out["afterResolve"]
    assert out["afterResolve"]["rotate"] == "none", out["afterResolve"]
    assert out["afterResolve"]["revoke"] == "none", out["afterResolve"]
    assert out["afterResolve"]["msg"] == "", out["afterResolve"]


@pytest.mark.parametrize("template", ["report.html", "reports.html"])
def test_revoke_response_after_format_switch_refreshes_from_current_selection(template):
    # TXT is active (Revoke is offered for it); CSV is not.
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-revoke'));
      changeTo('csv');
      await resolveFetch();
      out.afterResolve = snap();
      changeTo('txt');
      out.afterSwitchBack = snap();
    """, active_formats=("txt",))
    # The popup must not claim "revoked" / show the captured
    # format's post-revoke buttons under the CSV selection; it
    # refreshes from CSV's (inactive) state instead.
    assert out["afterResolve"]["msg"] == "", out["afterResolve"]
    assert out["afterResolve"]["create"] == "", out["afterResolve"]
    assert out["afterResolve"]["rotate"] == "none", out["afterResolve"]
    assert out["afterResolve"]["revoke"] == "none", out["afterResolve"]
    assert out["afterResolve"]["display"] == "none", out["afterResolve"]
    # The removal for the CAPTURED format still applied: back on
    # TXT, TXT is now inactive too (Create offered again).
    assert out["afterSwitchBack"]["create"] == "", out["afterSwitchBack"]
    assert out["afterSwitchBack"]["rotate"] == "none", out["afterSwitchBack"]
    assert out["afterSwitchBack"]["revoke"] == "none", out["afterSwitchBack"]


@pytest.mark.parametrize("template", ["report.html", "reports.html"])
def test_control_create_response_without_format_switch_displays_url(template):
    # CONTROL (not teeth): with no format switch before the
    # response arrives, the URL displays exactly as before the
    # round 3 fix — this test passes on both trees.
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-create'));
      await resolveFetch();
      out.afterResolve = snap();
    """, active_formats=())
    assert out["afterResolve"]["display"] == "block", out["afterResolve"]
    assert "TOKEN-TXT" in out["afterResolve"]["value"]
    assert "TOKEN-TXT" in out["afterResolve"]["mailto"]
    assert out["afterResolve"]["msg"] == "Share link created:", out["afterResolve"]
    assert out["afterResolve"]["create"] == "none", out["afterResolve"]
    assert out["afterResolve"]["rotate"] == "", out["afterResolve"]
    assert out["afterResolve"]["revoke"] == "", out["afterResolve"]
