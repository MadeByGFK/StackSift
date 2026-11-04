"""Issue #135 / PR #138 remediation round 2: one Codex P2 finding.

Round 2 finding (Codex review on head 38451dd8): the share popup's
link row was hidden on a format change only when the newly
selected format was NOT active. When TXT and CSV both had active
links, creating/rotating a TXT link displayed the TXT URL, and
selecting CSV left that TXT URL (and its Copy / Open-in-email
controls) visible — the user could distribute a TXT link while
CSV was selected. The identical flaw existed in both popups
(report page ``report.html`` and My Reports ``reports.html``).

Fix: each popup tracks ``displayedShareFormat`` — the format the
currently displayed URL belongs to, set by every create/rotate
success. ``refreshShareButtonsForSelectedFormat`` (and, on My
Reports, popup open) shows the row only when the displayed format
equals the selected format; on a mismatch it hides the row AND
clears the URL input, the mailto href, and the marker, so a stale
URL can neither be distributed under the wrong format nor be
resurrected by switching back. Revoking the displayed format
hides/clears the row. The server renders no per-format URLs into
either page, so hiding (not swapping in another URL) is correct.

Harness: following round 1's template-JS tests (which asserted on
the popup JS in the rendered templates), these tests go one step
further for a purely behavioural JS bug: they extract the actual
inline share script from each template, run it in Node against a
minimal DOM stub, and drive it exactly as a user would — open the
popup, create a link, switch formats, create/rotate/revoke —
asserting on the link row's display state and input value after
each step. No server behaviour is exercised here; the fetch stub
returns a distinct ``/s/TOKEN-<FORMAT>`` URL per format.

TEETH: every test in this file fails on the pre-fix tree
(c5730745 / remote head 38451dd8) and passes on the fixed tree —
verified by copying this file into a pristine checkout of
c5730745 and running it there (see the PR evidence).
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
globalThis.fetch = function (path, opts) {
  const fmt = opts && opts.body && opts.body.get ? opts.body.get('format') : 'txt';
  let body;
  if (path.indexOf('/revoke') !== -1) { body = { status: 'revoked' }; }
  else { body = { share_url: '/s/TOKEN-' + String(fmt).toUpperCase() }; }
  return Promise.resolve({
    ok: true, status: 200,
    json: function () { return Promise.resolve(body); },
  });
};
async function flush() { for (let i = 0; i < 6; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
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
           mailto: byId('share-mailto').href || '' };
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


def _run(template_name, scenario, *, active_formats=("txt", "csv")):
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
def test_a_displayed_url_hidden_and_cleared_on_switch_to_other_active_format(template):
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-create'));
      out.afterCreate = snap();
      changeTo('csv');
      out.afterSwitch = snap();
      changeTo('txt');
      out.afterSwitchBack = snap();
    """)
    assert out["afterCreate"]["display"] == "block"
    assert "TOKEN-TXT" in out["afterCreate"]["value"]
    # (a) TXT URL must not stay visible — nor copyable — under CSV.
    assert out["afterSwitch"]["display"] == "none", out["afterSwitch"]
    assert out["afterSwitch"]["value"] == "", out["afterSwitch"]
    assert "TOKEN-TXT" not in out["afterSwitch"]["mailto"]
    # Cleared state cannot be resurrected by switching back.
    assert out["afterSwitchBack"]["display"] == "none", out["afterSwitchBack"]
    assert out["afterSwitchBack"]["value"] == "", out["afterSwitchBack"]


@pytest.mark.parametrize("template", ["report.html", "reports.html"])
def test_b_switch_to_inactive_format_still_hides_and_clears(template):
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-create'));
      out.afterCreate = snap();
      changeTo('pdf');
      out.afterSwitch = snap();
    """)
    assert out["afterCreate"]["display"] == "block"
    # (b) existing behaviour preserved (row hidden) and the stale
    # URL is cleared rather than left in the hidden input.
    assert out["afterSwitch"]["display"] == "none", out["afterSwitch"]
    assert out["afterSwitch"]["value"] == "", out["afterSwitch"]


@pytest.mark.parametrize("template", ["report.html", "reports.html"])
def test_c_create_and_rotate_for_selected_format_show_its_url(template):
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-create'));
      out.afterTxtCreate = snap();
      changeTo('csv');
      out.afterSwitch = snap();
      await click(byId('share-create'));
      out.afterCsvCreate = snap();
      await click(byId('share-rotate'));
      out.afterCsvRotate = snap();
    """)
    assert "TOKEN-TXT" in out["afterTxtCreate"]["value"]
    assert out["afterSwitch"]["display"] == "none", out["afterSwitch"]
    assert out["afterSwitch"]["value"] == "", out["afterSwitch"]
    # (c) creating (and rotating) for the selected format shows
    # that format's own URL.
    assert out["afterCsvCreate"]["display"] == "block", out["afterCsvCreate"]
    assert "TOKEN-CSV" in out["afterCsvCreate"]["value"]
    assert out["afterCsvRotate"]["display"] == "block", out["afterCsvRotate"]
    assert "TOKEN-CSV" in out["afterCsvRotate"]["value"]


@pytest.mark.parametrize("template", ["report.html", "reports.html"])
def test_d_revoke_of_displayed_format_hides_and_clears(template):
    out = _run(template, _OPEN[template] + """
      changeTo('txt');
      await click(byId('share-create'));
      out.afterCreate = snap();
      await click(byId('share-revoke'));
      out.afterRevoke = snap();
    """)
    assert out["afterCreate"]["display"] == "block"
    assert out["afterRevoke"]["display"] == "none", out["afterRevoke"]
    assert out["afterRevoke"]["value"] == "", out["afterRevoke"]
