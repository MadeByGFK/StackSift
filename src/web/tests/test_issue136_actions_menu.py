"""Issue #136: consolidation pass — one job per page.

Founder rule (2026-11-03): Analyze = do the thing, Report = read the
result, My Reports = manage reports, Settings = the account.

Contract built here (presentation only — no route, charge, or pricing
code changes):

- ``report.html``: the Export · Analysis · Share button row collapses
  into ONE "Actions" menu holding the SAME actions in the SAME order
  (Export PDF/CSV/JSON forms with their #129 data-confirm popups,
  then Analysis — modal opener or link to an existing Analysis
  Report — then Share, opening the existing share modal). No
  capability removed; nothing account-level on the page.
- ``deep_dive_report.html`` (Analysis Report page): its Export
  dropdown becomes the same single Actions menu (export forms only —
  that page has no Analysis/Share actions of its own).
- ``batch_report.html`` / ``compare_report.html``: LEFT as a single
  direct "Export PDF (2 credits)" button — each has exactly ONE
  action (PDF only), so there is nothing to consolidate and a
  one-item menu would hide the up-front price behind an extra click.
- ``reports.html`` (My Reports): the full row View · Export ·
  Analysis · Share · Extend is unchanged, including the PR #139
  suppression of Share and Extend on deep_dive rows.
- ``settings.html``: unchanged — Credits and Report Access already
  live on the account page.

Consistency fix (the #129 closure quirk): the PDF fetch handler in
``auth_form_script.html`` disabled the submit button and re-enabled
it ONLY on a network exception, so after a completed PDF download
the menu item stayed disabled in-session until a reload. The button
is now re-enabled in a ``finally`` block (in-flight guard only).

TEETH: the Actions-menu structure tests and both Node harness tests
fail on the pre-build tree (base a5513081) and pass on the built
tree. The batch/compare, My Reports, and Settings tests pass on both
trees BY DESIGN — they guard decisions/regressions on pages this
pass deliberately does not change.
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


def _menu_slice(html):
    start = html.index('id="actions-menu"')
    end = html.index('id="analysis-modal"') if 'id="analysis-modal"' in html \
        else html.index('id="ss-confirm"')
    return html[start:end]


# --- report page: one Actions menu -------------------------------------------

def test_report_page_single_actions_menu_holds_all_actions(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    text = page.text
    # Exactly one menu trigger and one menu; old row triggers gone.
    assert text.count('id="actions-btn"') == 1
    assert text.count('id="actions-menu"') == 1
    assert ">Actions</button>" in text
    assert 'id="export-btn"' not in text
    assert 'id="export-dropdown"' not in text
    menu = _menu_slice(text)
    # Same actions, same order: Export PDF/CSV/JSON, Analysis, Share.
    pdf_at = menu.index(f'action="/reports/{rid}/pdf"')
    csv_at = menu.index(f'action="/reports/{rid}/exports/csv"')
    json_at = menu.index(f'action="/reports/{rid}/exports/json"')
    analysis_at = menu.index('id="analysis-btn"')
    share_at = menu.index('id="share-btn"')
    assert pdf_at < csv_at < json_at < analysis_at < share_at
    assert ">Export PDF</button>" in menu
    assert ">Export CSV</button>" in menu
    assert ">Export JSON</button>" in menu
    # The #129 confirmation behaviour is intact on every export form.
    assert menu.count("data-confirm") == 3
    assert "Export costs 2 credits and unlocks PDF, CSV and JSON" in menu
    # The modals the menu items open are still on the page, unchanged.
    assert 'id="analysis-modal"' in text
    assert 'id="share-modal"' in text
    assert 'id="ss-confirm"' in text
    # Nothing account-level / manage-level leaked onto the read page:
    # no retention (Extend) form and no share FORM (the share modal
    # posts via fetch, as before).
    assert f'action="/reports/{rid}/retention"' not in text
    assert f'action="/reports/{rid}/share"' not in text


def test_report_page_actions_menu_links_to_existing_analysis(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    analysis_id = gen.json()["analysis_result_id"]
    page = auth_env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    menu = _menu_slice(page.text)
    # With an Analysis Report already generated, the menu item is the
    # link to it (no second charge path) and the modal opener is gone.
    assert f'href="/reports/{analysis_id}"' in menu
    assert ">Analysis</a>" in menu
    assert 'id="analysis-btn"' not in page.text
    assert 'id="share-btn"' in menu


def test_analysis_report_page_single_actions_menu(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    analysis_id = gen.json()["analysis_result_id"]
    page = auth_env.client.get(f"/reports/{analysis_id}")
    assert page.status_code == 200
    text = page.text
    assert text.count('id="actions-btn"') == 1
    assert text.count('id="actions-menu"') == 1
    assert 'id="export-btn"' not in text
    assert 'id="export-dropdown"' not in text
    menu = _menu_slice(text)
    assert f'action="/reports/{analysis_id}/pdf"' in menu
    assert f'action="/reports/{analysis_id}/exports/csv"' in menu
    assert f'action="/reports/{analysis_id}/exports/json"' in menu
    assert menu.count("data-confirm") == 3
    # The Analysis Report page has no Analysis/Share actions.
    assert 'id="analysis-btn"' not in text
    assert 'id="share-btn"' not in text


# --- batch / compare: deliberately left as one direct button -----------------

def _render(template_name, **ctx):
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env_j = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                        autoescape=select_autoescape(["html"]))
    return env_j.get_template(template_name).render(**ctx)


def test_batch_and_compare_keep_single_direct_pdf_button():
    from test_batch_service import _context_payload
    payload = _context_payload()
    batch_html = _render(
        "batch_report.html",
        filename=payload["filename"],
        summary_sentence=payload["summary_sentence"],
        summary=payload["summary"],
        combined_issues=payload["combined_issues"],
        files=payload["files"],
        current_user=object(), report_id=42, csrf_token="csrf-test")
    compare_html = _render(
        "compare_report.html",
        filename="cmp.log", no_material_differences=False,
        resolved_note="note", current_user=object(), report_id=43,
        csrf_token="csrf-test",
        summary={"new": 0, "resolved": 0, "volume_changed": 0,
                 "severity_shifted": 0},
        shared=[], new=[], resolved=[], volume_changes=[],
        severity_shifts=[],
        material_change={"version": 1, "min_absolute": 3,
                         "min_fraction_of_a": 0.5})
    for html in (batch_html, compare_html):
        assert "Export PDF (2 credits)" in html
        assert 'id="actions-btn"' not in html
        assert 'id="actions-menu"' not in html
        assert html.count('action="/reports/') == 1


# --- My Reports + Settings: unchanged pages, regression guards ----------------

def test_my_reports_row_keeps_full_actions_and_deep_dive_suppression(auth_env):
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

    normal = _card_for(str(rid))
    assert "export-toggle" in normal and ">Export</button>" in normal
    assert "share-open" in normal and ">Share</button>" in normal
    assert f"/reports/{rid}/retention" in normal and ">Extend</button>" in normal
    # PR #139 remediation F2 + Extend guard: deep_dive rows keep
    # neither Share nor Extend (both routes 404 for those rows).
    deep = _card_for(str(analysis_id))
    assert "share-open" not in deep and ">Share</button>" not in deep
    assert "Extend" not in deep
    assert f"/reports/{analysis_id}/retention" not in deep


def test_settings_keeps_account_features(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    page = auth_env.client.get("/settings")
    assert page.status_code == 200
    for marker in ("Account settings", "Credits", 'id="purchase-history"',
                   "Purchase history", 'id="report-access"', "Report Access",
                   "Connected accounts", "Active sessions"):
        assert marker in page.text, marker


# --- Node harnesses: menu behaviour + the PDF re-enable fix -------------------

pytestmark_js = pytest.mark.skipif(
    shutil.which("node") is None, reason="node required for template JS tests")

_JS_HARNESS = r"""
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
  appendChild() {}
  remove() {}
  click() {}
}
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
['export-btn','export-dropdown','actions-btn','actions-menu',
 'ss-confirm','ss-confirm-text','ss-confirm-yes','ss-confirm-no',
 'share-modal','share-msg','share-link-row','share-link','share-mailto',
 'share-create','share-rotate','share-revoke','share-close',
 'share-btn','share-copy','analysis-modal','analysis-btn',
 'analysis-close','analysis-confirm'].forEach(byId);
const radios = ['txt','pdf','json','csv'].map(function (v) {
  const r = new El('radio-' + v); r.value = v; r.name = 'share-format'; return r;
});
radios[0].checked = true;
globalThis.window = globalThis;
globalThis.location = { origin: 'https://example.test' };
globalThis.document = {
  getElementById: byId,
  querySelectorAll: function (sel) {
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
globalThis.fetch = function () { return Promise.reject(new Error('no fetch in menu harness')); };
async function flush() { for (let i = 0; i < 6; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
async function click(el) {
  (el.listeners.click || []).forEach(function (fn) {
    fn({ preventDefault: function () {}, stopImmediatePropagation: function () {} });
  });
  await flush();
}
"""


def _run_js(script, scenario):
    full = (_JS_HARNESS + "\n" + script + "\n(async () => {\n  const out = {};\n"
            + scenario + "\n  console.log('RESULT:' + JSON.stringify(out));\n"
            "})().catch(function (e) { console.error(e && e.stack || e); process.exit(3); });\n")
    proc = subprocess.run(["node", "-e", full], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"node harness failed:\n{proc.stdout}\n{proc.stderr}"
    line = next(l for l in proc.stdout.splitlines() if l.startswith("RESULT:"))
    return json.loads(line[len("RESULT:"):])


def _inline_script(template_name, marker):
    html = (_TEMPLATES / template_name).read_text()
    for script in re.findall(r"<script>(.*?)</script>", html, re.S):
        if marker in script:
            return script
    raise AssertionError(f"script with {marker!r} not found in {template_name}")


def _menu_script(template_name):
    script = _inline_script(template_name, "ss-confirm")
    script = script.replace("{{ share_create_key }}", "create-key")
    script = script.replace("{{ share_rotate_key }}", "rotate-key")
    script = script.replace("{{ share_revoke_key }}", "revoke-key")
    script = script.replace("{{ csrf_token }}", "csrf-test")
    script = script.replace("{{ report_id }}", "RID")
    script = re.sub(r"var shareActiveFormats = .*?;",
                    "var shareActiveFormats = [];", script, count=1, flags=re.S)
    return script


@pytestmark_js
def test_actions_menu_toggles_on_report_and_analysis_pages():
    for template in ("report.html", "deep_dive_report.html"):
        out = _run_js(_menu_script(template), """
          out.initial = byId('actions-menu').style.display || '';
          await click(byId('actions-btn'));
          out.openDisplay = byId('actions-menu').style.display || '';
          out.openAria = byId('actions-btn').getAttribute('aria-expanded');
          await click(byId('actions-btn'));
          out.closedDisplay = byId('actions-menu').style.display || '';
          out.closedAria = byId('actions-btn').getAttribute('aria-expanded');
        """)
        assert out["openDisplay"] == "block", (template, out)
        assert out["openAria"] == "true", (template, out)
        assert out["closedDisplay"] == "none", (template, out)
        assert out["closedAria"] == "false", (template, out)


@pytestmark_js
def test_actions_menu_items_open_existing_modals_and_close_menu():
    out = _run_js(_menu_script("report.html"), """
      await click(byId('actions-btn'));
      await click(byId('share-btn'));
      out.afterShareMenu = byId('actions-menu').style.display || '';
      out.afterShareModal = byId('share-modal').style.display || '';
      await click(byId('actions-btn'));
      await click(byId('analysis-btn'));
      out.afterAnalysisMenu = byId('actions-menu').style.display || '';
      out.afterAnalysisModal = byId('analysis-modal').style.display || '';
    """)
    assert out["afterShareModal"] == "flex", out
    assert out["afterShareMenu"] == "none", out
    assert out["afterAnalysisModal"] == "flex", out
    assert out["afterAnalysisMenu"] == "none", out


_PDF_HARNESS = r"""
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
  appendChild() {}
  remove() {}
  click() {}
}
const pdfButton = { disabled: false };
const pdfForm = new El('pdf-form');
pdfForm.action = '/reports/RID/pdf';
pdfForm.querySelector = function (sel) {
  return sel.indexOf('submit') !== -1 ? pdfButton : null;
};
pdfForm.hasAttribute = function () { return false; };
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
globalThis.window = globalThis;
globalThis.location = { origin: 'https://example.test', assign: function () {} };
globalThis.URL = { createObjectURL: function () { return 'blob:x'; },
                   revokeObjectURL: function () {} };
globalThis.FormData = class { constructor(form) {} };
globalThis.document = {
  getElementById: byId,
  createElement: function () { return new El('created'); },
  body: new El('body'),
  addEventListener: function () {},
  querySelectorAll: function (sel) {
    if (sel === 'form[action$="/pdf"]') { return [pdfForm]; }
    return [];
  },
  querySelector: function () { return null; },
};
let fetchMode = 'ok';
globalThis.fetch = function () {
  if (fetchMode === 'ok') {
    return Promise.resolve({
      ok: true, status: 200,
      blob: function () { return Promise.resolve({}); },
      headers: { get: function () { return 'attachment; filename="report.pdf"'; } },
      json: function () { return Promise.resolve({}); },
    });
  }
  return Promise.resolve({
    ok: false, status: 402,
    json: function () { return Promise.resolve({ error: 'Export failed. Please try again.' }); },
  });
};
async function flush() { for (let i = 0; i < 10; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
async function submitPdf() {
  pdfButton.disabled = false;
  const handlers = pdfForm.listeners.submit || [];
  for (const fn of handlers) { await fn({ preventDefault: function () {} }); }
  await flush();
  return pdfButton.disabled;
}
"""


@pytestmark_js
def test_pdf_button_reenabled_after_download_and_after_error():
    script = (_TEMPLATES / "auth_form_script.html").read_text()
    script = re.search(r"<script>(.*?)</script>", script, re.S).group(1)
    full = (_PDF_HARNESS + "\n" + script + "\n(async () => {\n  const out = {};\n"
            "  fetchMode = 'ok';\n  out.afterDownload = await submitPdf();\n"
            "  fetchMode = 'err';\n  out.afterError = await submitPdf();\n"
            "  console.log('RESULT:' + JSON.stringify(out));\n"
            "})().catch(function (e) { console.error(e && e.stack || e); process.exit(3); });\n")
    proc = subprocess.run(["node", "-e", full], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"node harness failed:\n{proc.stdout}\n{proc.stderr}"
    line = next(l for l in proc.stdout.splitlines() if l.startswith("RESULT:"))
    out = json.loads(line[len("RESULT:"):])
    # The #129 quirk: the button stayed disabled (true) after a
    # completed download and after an error response, until reload.
    assert out["afterDownload"] is False, out
    assert out["afterError"] is False, out
