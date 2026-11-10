"""Issue #170 S3: My Reports-surface design-alignment port.

Spec v1 Decision 8 + the My Reports port plan, as amended by spec
v2 amendments A4 (NO Delete action exists — it was invented from
the remake mock and is removed from the inventory; ALL JS
selector/ancestor assumptions enumerated and preserved; type-specific
action ABSENCES preserved as strictly as presences; new browser
tests required), A7 (surface-scoped styles + nonported-surface
check) and A8 (teeth discipline; premise-changed tests named before
editing).

Mapping built here (presentation only):
  reports.html <- the remake's table presentation: columns Report /
                  Date / Severity / State & retention / Actions;
                  page header gains the eyebrow treatment; the
                  empty state is restyled; a severity pill component
                  renders the row's existing severity value. Every
                  data attribute and JS hook is carried over BY NAME.
                  The row element keeps the .card class because the
                  retention JS scopes its per-row update with
                  form.closest('.card') and then queries the expiry
                  elements within that row (A4 ancestor contract —
                  preserved, no adapter needed). State & retention
                  cell wording is byte-identical to the base cards
                  ("Expires <date>" + "Expires in N day(s)"); the
                  remake's "90 days" phrasing does NOT appear in the
                  cell — retention lengths are #164-model facts, not
                  styling, and under the interim credit model the
                  truthful wording is the 7-day / extended states the
                  base already renders.
  style.css    <- one .s3- block, pure addition, placed BEFORE the
                  S2 block: the S2 test slices style.css from its
                  marker to the S4 marker and the S4 test slices
                  from its marker to EOF, so a block between S2 and
                  S4 or after S4 would break an unmodified scope
                  test. reports.html does not link the shared
                  stylesheet (its styles are the page-local <style>
                  block), so the functional S3 rules live in
                  reports.html itself, in the page's own tokens; the
                  style.css block is the shared-token record.

Teeth discipline (A8): tests asserting the NEW structure (table,
thead columns, eyebrow, severity pill, .s3- CSS blocks, s3-empty)
FAIL on the base tree (2eaf1364) for structural reasons and pass on
the built tree. Tests pinning pre-existing behaviour verbatim
(action inventory and absences per row type, hook/confirm parity,
retention wording, header/nav, no-charging, the A4 browser
behaviours) are regression gates — they pass on both trees and are
labelled as such; a gate is not teeth.
"""

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from app import auth
from app.main import templates
from app.models import Consent, CreditLedger, Operation, User

APP = Path(__file__).resolve().parents[1] / "app"
CSS = (APP / "static" / "style.css").read_text()
REPORTS = (APP / "templates" / "reports.html").read_text()

_TS = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
_EXP = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

_LOCKED = "Export costs 2 credits and unlocks PDF, CSV and JSON for this report."
_FREE = {
    "pdf": "This report is export-unlocked — the PDF download is free.",
    "csv": "This report is export-unlocked — the CSV download is free.",
    "json": "This report is export-unlocked — the JSON download is free.",
}
_EXTEND_CONFIRM = "Extend this report's retention by 90 days for 1 credit?"


def _report(**overrides):
    row = {
        "id": "11111111-1111-1111-1111-111111111111",
        "filename": "app.log",
        "severity": "warnings",
        "type": "analysis",
        "report_kind": None,
        "created_at": _TS,
        "expires_at": _EXP,
        "days_left": 7,
        "redemption_only": False,
        "export_unlocked": False,
        "share_active": False,
        "share_formats": [],
        "share_create_key": "create-key",
        "share_rotate_key": "rotate-key",
        "share_revoke_key": "revoke-key",
        "retention_key": "retention-key",
        "analysis_eligible": True,
        "analysis_reason": None,
        "analysis_result_id": None,
        "entitlement_available": False,
        "redemption_deadline": "2026-12-11",
    }
    row.update(overrides)
    return row


def _render(reports, **overrides):
    ctx = {
        "reports": reports,
        "current_user": SimpleNamespace(email="owner@example.com"),
        "csrf_token": "csrf-test",
        "total": len(reports),
        "page": 1,
        "total_pages": 1,
        "product_ready": True,
    }
    ctx.update(overrides)
    return templates.env.get_template("reports.html").render(**ctx)


def _row_for(html, report_id):
    view_link = f'href="/reports/{report_id}" class="btn btn-ghost">View'
    rows = html.split('<tr class="card s3-row">')
    matches = [r for r in rows if view_link in r]
    assert len(matches) == 1, report_id
    return matches[0].split("</tr>")[0]


# --- New table structure (TEETH) --------------------------------------------


def test_s3_table_structure_and_columns():
    html = _render([_report()])
    assert '<table class="s3-table">' in html
    assert '<div class="s3-table-wrap">' in html
    head = html[html.index("<thead>"):html.index("</thead>")]
    cols = [head.index(f">{name}<") for name in
            ("Report", "Date", "Severity", "State &amp; retention",
             "Actions")]
    assert cols == sorted(cols), cols
    assert html.count('<tr class="card s3-row">') == 1
    # The card list is gone (structure teeth, not a copy gate).
    assert '<ul class="list">' not in html
    assert '<li class="card">' not in html
    # A4 ancestor contract: the row keeps .card so the retention
    # JS's form.closest('.card') keeps working unmodified.
    assert "form.closest('.card')" in html or \
        'form.closest(".card")' in html or "closest('.card')" in html
    assert "closest('.card')" in REPORTS


def test_s3_page_head_eyebrow_and_empty_state():
    html = _render([_report()])
    assert '<p class="s3-eyebrow">Manage</p>' in html
    assert html.index('class="s3-eyebrow"') < html.index(
        "<h1>My Reports</h1>")
    assert "Your analysis reports from the last 7 days." in html
    empty = _render([])
    assert '<div class="empty s3-empty">' in empty
    assert "No reports yet. Analyze a log file to get started." in empty
    assert "Reports are kept for 7 days after analysis." in empty
    assert '<a href="/" class="btn btn-primary">Analyze a log file</a>' \
        in empty


def test_s3_severity_pill_per_row_state():
    """Teeth: the pill is new markup; its label/class derive from the
    row's existing severity value ('ok'|'warnings'|'errors'|None),
    and the base severity dot is carried over unchanged."""
    cases = [
        ("ok", "s3-pill ok", ">OK<", "dot ok"),
        ("warnings", "s3-pill warnings", ">Warnings<", "dot warn"),
        ("errors", "s3-pill errors", ">Errors<", "dot err"),
        (None, "s3-pill neutral", ">—<", "dot neutral"),
    ]
    for severity, pill_cls, label, dot_cls in cases:
        rid = f"rid-{severity}"
        html = _render([_report(id=rid, severity=severity)])
        row = _row_for(html, rid)
        assert f'class="{pill_cls}"' in row, severity
        assert label in row, severity
        assert f'class="{dot_cls}"' in row, severity


def test_s3_css_blocks_are_s3_scoped():
    """A7 teeth: the S3 blocks exist (shared style.css + the page's
    own <style>, where the functional rules live) and every selector
    in each is .s3- scoped."""
    marker = "Issue #170 S3"
    assert marker in CSS
    block = CSS[CSS.index(marker):CSS.index("Issue #170 S2")]
    selectors = re.findall(r"([^{}]+)\{", block)
    assert selectors, "no rules in the style.css S3 block"
    for sel in selectors:
        if sel.strip().startswith("@media"):
            continue
        assert ".s3" in sel, f"unscoped selector in S3 block: {sel!r}"
    assert ".s3-pill" in block and ".s3-table" in block
    inline = REPORTS[REPORTS.index(marker):REPORTS.index("</style>")]
    iselectors = re.findall(r"([^{}]+)\{", inline)
    assert iselectors, "no rules in the reports.html S3 block"
    for sel in iselectors:
        if sel.strip().startswith("@media"):
            continue
        assert ".s3" in sel, f"unscoped inline selector: {sel!r}"
    assert ".s3-pill" in inline and "var(--accent)" in inline


# --- Action inventory + absences per row type (gates, A4) -------------------


def test_s3_normal_row_full_action_inventory():
    rid = "row-normal"
    row = _row_for(_render([_report(id=rid)]), rid)
    assert ">View</a>" in row
    assert "export-toggle" in row and ">Export</button>" in row
    assert f'id="menu-{rid}"' in row
    assert f'action="/reports/{rid}/pdf"' in row
    assert f'action="/reports/{rid}/exports/csv"' in row
    assert f'action="/reports/{rid}/exports/json"' in row
    assert row.count("data-confirm") == 4  # 3 exports + Extend
    assert row.count(f'data-confirm="{_LOCKED}"') == 3
    assert "analysis-open" in row and ">Analysis</button>" in row
    assert "share-open" in row and ">Share</button>" in row
    assert f'action="/reports/{rid}/retention"' in row
    assert ">Extend</button>" in row
    # Hooks present per row (A4 / spec parity list).
    assert row.count("data-retention-expiry-date") == 1
    assert row.count("data-retention-expiry-pill") == 1
    assert row.count("data-retention-status") == 1


def test_s3_unlocked_row_export_confirms_are_free_text():
    rid = "row-unlocked"
    row = _row_for(_render([_report(id=rid, export_unlocked=True)]), rid)
    for fmt in ("pdf", "csv", "json"):
        assert f'data-confirm="{_FREE[fmt]}"' in row, fmt
    assert _LOCKED not in row


def test_s3_comparison_and_batch_rows_omit_csv_json():
    """A4 absence gate: CSV/JSON export forms are omitted for
    comparison and batch rows (the routes reject them); PDF, Share
    and Extend remain."""
    comp = _row_for(_render([_report(
        id="row-comp", type="comparison", analysis_eligible=False)]),
        "row-comp")
    assert 'action="/reports/row-comp/pdf"' in comp
    assert "/exports/csv" not in comp and "/exports/json" not in comp
    assert "share-open" in comp and "retention" in comp
    assert "analysis-open" not in comp  # Analysis is analysis-type only
    batch = _row_for(_render([_report(
        id="row-batch", report_kind="batch")]), "row-batch")
    assert 'action="/reports/row-batch/pdf"' in batch
    assert "/exports/csv" not in batch and "/exports/json" not in batch
    assert "share-open" in batch and "retention" in batch


def test_s3_deep_dive_row_action_gates():
    """A4 absence gate: deep_dive rows keep View + Export (all
    formats) but have NO Share and NO Extend (both routes 404 for
    them), carry the 'Investigation Report' kind title, and read
    'Created', never 'Analyzed' (#144 semantics retained)."""
    rid = "row-deep"
    row = _row_for(_render([_report(
        id=rid, type="deep_dive", filename="deep-source.log",
        analysis_eligible=False)]), rid)
    assert '<div class="kind-title">Investigation Report</div>' in row
    assert row.index("Investigation Report") < row.index("deep-source.log")
    assert re.search(r"Created 2026-11-04 12:00", row)
    assert "Analyzed" not in row
    assert 'action="/reports/row-deep/pdf"' in row
    assert 'action="/reports/row-deep/exports/csv"' in row
    assert "share-open" not in row and ">Share</button>" not in row
    assert "Extend" not in row and "/retention" not in row
    assert "analysis-open" not in row


def test_s3_analysis_link_vs_purchase_popup():
    """A4 gate: an already-purchased source row LINKS to its
    Investigation Report; an eligible unpurchased row opens the purchase
    popup (analysis-open) with its per-row state attributes."""
    done = _row_for(_render([_report(
        id="row-done", analysis_result_id="derived-1")]), "row-done")
    assert '<a href="/reports/derived-1" class="btn btn-ghost">' \
           "Analysis</a>" in done
    assert "analysis-open" not in done
    todo = _row_for(_render([_report(id="row-todo")]), "row-todo")
    assert "analysis-open" in todo
    assert 'data-report="row-todo"' in todo
    assert 'data-eligible="1"' in todo
    assert 'data-deadline="2026-12-11"' in todo


def test_s3_redemption_only_row_suppressions():
    """Gate: redemption-only rows keep View + Analysis (the redeem
    path) and suppress Export/Share/Extend (they would 410), with
    the redemption label in the State cell."""
    rid = "row-redeem"
    row = _row_for(_render([_report(id=rid, redemption_only=True)]), rid)
    assert "Redemption only — this report has expired" in row
    assert "export-toggle" not in row
    assert "share-open" not in row
    assert "Extend" not in row
    assert "analysis-open" in row


def test_s3_no_delete_action_anywhere():
    """A4 gate: Delete was invented from the remake mock — no Delete
    action, form, or route hint exists on this surface."""
    html = _render([_report(), _report(
        id="row-2", type="deep_dive", filename="other.log")])
    assert "Delete" not in html
    assert "/delete" not in html


def test_s3_batch_entry_card_under_table():
    """Founder ruling 2026-11-09 (~21:11 ET): Batch is discoverable
    from My Reports itself via an entry card under the table, mirroring
    the S2 Analyze card's approved copy verbatim — no price, size or
    retention claim beyond the file-count wording S2 already carries.
    Teeth: the card is new markup, absent on the base surface."""
    html = _render([_report(id="row-batch-card")])
    assert 'data-s3-entry="batch"' in html
    card = html[html.index('data-s3-entry="batch"'):]
    card = card[:card.index("</a>")]
    assert 'href="/batch"' in html[:html.index('data-s3-entry="batch"')]
    assert "Batch analysis" in card
    assert ("Upload 2 to 5 log files and get one combined report, "
            "in upload order.") in card
    assert "Start a batch →" in card
    # The card sits under the table, before the pager/empty-state close.
    assert html.index("</table>") < html.index('data-s3-entry="batch"')


def test_s3_retired_product_names_absent():
    """Founder naming sweep (ruled 2026-11-09, applied on this
    surface in S3): the retired user-facing names "Analysis Report"
    and "Investigation Brief" appear nowhere in reports.html; the
    paid deliverable is "Investigation Report" in the kind title,
    the modal actions, and the JS result messages. (The short
    "Analysis" row-action label is the action label, not the
    deliverable name, and is retained.) Teeth: the base template
    carries all five retired-name strings, so this fails on base."""
    assert "Analysis Report" not in REPORTS
    assert "Investigation Brief" not in REPORTS
    assert '<div class="kind-title">Investigation Report</div>' in REPORTS
    assert ">View Investigation Report</a>" in REPORTS
    assert ">Generate Investigation Report</button>" in REPORTS
    assert "'Investigation Report ready.'" in REPORTS
    assert REPORTS.count("Investigation Report generation failed.") == 2


def test_s3_hooks_and_confirm_texts_verbatim():
    """Gate: every JS hook / data attribute carried over by name,
    with byte-identical confirm texts and per-row keys."""
    rid = "row-hooks"
    html = _render([_report(id=rid)])
    row = _row_for(html, rid)
    assert f'data-menu="menu-{rid}"' in row
    assert 'aria-haspopup="true"' in row
    assert f'data-confirm="{_EXTEND_CONFIRM}"' in row
    assert "data-retention-form" in row
    assert 'name="idempotency_key" value="retention-key"' in row
    assert 'data-create-key="create-key"' in row
    assert 'data-rotate-key="rotate-key"' in row
    assert 'data-revoke-key="revoke-key"' in row
    assert 'data-formats=""' in row and 'data-unlocked=""' in row
    assert row.count('name="csrf_token"') == 4  # 3 exports + Extend
    # Shared modals and their hooks survive verbatim.
    for marker in ('id="ss-confirm"', 'id="extend-modal"',
                   'id="analysis-modal"', 'id="share-modal"',
                   'id="share-format-choice"', 'name="share-format"',
                   "window.__productReady"):
        assert marker in html, marker


def test_s3_retention_cell_matches_actual_state():
    """Gate (Decision 8 wording rule): the State & retention cell
    renders the row's actual expiry/days-left, in the base wording;
    the remake's '90 days' phrasing never appears in the cell."""
    row = _row_for(_render([_report(id="row-state")]), "row-state")
    state = row[row.index('class="s3-state-cell"'):
                row.index('class="s3-actions-cell"')]
    assert "Expires 2026-11-11" in state
    assert "Expires in 7 days" in state
    assert "90 days" not in state
    soon = _row_for(_render([_report(
        id="row-soon", days_left=1,
        expires_at=datetime(2026, 11, 5, 12, 0,
                            tzinfo=timezone.utc))]), "row-soon")
    sstate = soon[soon.index('class="s3-state-cell"'):]
    assert "Expires in 1 day" in sstate
    assert 'class="expiry soon"' in sstate


def test_s3_header_nav_unchanged():
    """Gate: canonical lockup, mobile toggle + nav_script preserved;
    no Pricing label is introduced early (S5, Decision 11)."""
    html = _render([])
    assert '<a href="/" class="logo">stacksift<span>.</span></a>' in html
    assert 'class="nav-toggle"' in html
    assert 'aria-controls="site-nav"' in html
    assert '<a href="/reports" class="active">My Reports</a>' in html
    assert "nav_script.html" in REPORTS
    assert ">Pricing<" not in html


# --- Live route: structure (teeth) + no-charging (gate) ---------------------


def _login_user(env, email="owner@example.com"):
    with env.sessions() as db:
        user = User(email=email, email_verified=True,
                    password_hash=auth.hash_password("Str0ng!Passw0rd"))
        db.add(user)
        db.commit()
        session, raw = auth.create_session(db, user.id)
        csrf = session.csrf_token
    env.client.cookies.set(auth.SESSION_COOKIE, raw,
                           domain="testserver.local", path="/")
    env.client.headers["X-CSRF-Token"] = csrf
    return csrf


def _row_counts(env):
    with env.sessions() as db:
        return (db.query(Operation).count(),
                db.query(Consent).count(),
                db.query(CreditLedger).count())


def test_s3_live_reports_page_table_and_no_charging_rows(auth_env):
    from test_structured_export_e2e import _setup
    _, user_id, rid, csrf = _setup(auth_env)
    before = _row_counts(auth_env)
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    # Teeth on the live route: the table composition renders with
    # the real row's hooks.
    for marker in ('<table class="s3-table">', 'class="s3-eyebrow"',
                   '<tr class="card s3-row">', 'class="s3-pill',
                   "data-retention-expiry-pill",
                   "data-retention-expiry-date"):
        assert marker in page.text, marker
    assert '<li class="card">' not in page.text
    # Gate: rendering this surface creates no charging rows
    # (Decision 12).
    auth_env.client.get("/reports")
    assert _row_counts(auth_env) == before


def test_s3_nonported_surfaces_carry_no_s3_markup(auth_env):
    """A7 nonported-surface check: Pricing (/credits), Login,
    Settings and Analyze render with no s3 markup; the control
    (My Reports itself) DOES carry it, so the check is not vacuous.
    The sample is a passenger surface: it renders deep_dive_report
    markup and must carry no s3 markup either."""
    _login_user(auth_env)
    for path in ("/", "/credits", "/login", "/settings"):
        page = auth_env.client.get(path)
        assert page.status_code == 200, (path, page.status_code)
        assert "s3-" not in page.text, path
        assert 'class="nav-toggle"' in page.text, path
    control = auth_env.client.get("/reports")
    assert control.status_code == 200
    assert "s3-eyebrow" in control.text and "s3-empty" in control.text
    from app import deep_dive as dd
    from test_issue162_brief import _sample_artifact
    projection = dd.public_projection(_sample_artifact())
    html = templates.env.get_template("deep_dive_report.html").render(
        analysis_projection=projection, filename="sample.log",
        is_sample=True,
        branding={"business_name": "WellInstance",
                  "client_name": None, "report_title": None,
                  "accent": None, "logo_url": None})
    assert "s3-" not in html
    assert "SAMPLE" in html


# --- A4 browser tests (Node harness over the real inline script) ------------

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
  requestSubmit() {}
}
Date.now = function () { return Date.parse('2026-11-04T12:00:00Z'); };
const els = {};
function byId(id) { if (!els[id]) { els[id] = new El(id); } return els[id]; }
['ss-confirm','ss-confirm-text','ss-confirm-yes','ss-confirm-no',
 'extend-modal','extend-msg','extend-close',
 'share-modal','share-msg','share-link-row','share-link','share-mailto',
 'share-create','share-rotate','share-revoke','share-close','share-copy',
 'analysis-modal','analysis-msg','analysis-confirm','analysis-close',
 'analysis-link-row','analysis-view','credit-badge'].forEach(byId);
byId('credit-badge').textContent = '\u{1FA99} 3 credits';
const radios = ['txt','pdf','json','csv'].map(function (v) {
  const r = new El('radio-' + v); r.value = v; r.name = 'share-format'; return r;
});
radios[0].checked = true;
function makeRow(prefix, expiryText, pillText) {
  const dateEl = new El(prefix + '-date'); dateEl.textContent = expiryText;
  const pillEl = new El(prefix + '-pill'); pillEl.textContent = pillText;
  const statusEl = new El(prefix + '-status'); statusEl.style.display = 'none';
  const rowEl = new El(prefix + '-row');
  rowEl.querySelector = function (sel) {
    if (sel === '[data-retention-expiry-date]') { return dateEl; }
    if (sel === '[data-retention-expiry-pill]') { return pillEl; }
    if (sel === '[data-retention-status]') { return statusEl; }
    return null;
  };
  const btn = { disabled: false };
  const form = new El(prefix + '-form');
  form.action = '/reports/' + prefix + '/retention';
  form._row = rowEl;
  form.getAttribute = function (k) {
    if (k === 'data-confirm') { return "Extend this report's retention by 90 days for 1 credit?"; }
    return El.prototype.getAttribute.call(this, k);
  };
  form.querySelector = function (sel) { return sel.indexOf('submit') !== -1 ? btn : null; };
  form.closest = function (sel) { return sel === '.card' ? rowEl : null; };
  form.requestSubmit = function () { dispatchSubmit(form); };
  return { form: form, rowEl: rowEl, dateEl: dateEl, pillEl: pillEl, statusEl: statusEl, btn: btn };
}
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
function makeShareBtn(prefix) {
  const b = new El(prefix + '-share');
  b.setAttribute('data-report', prefix);
  b.setAttribute('data-create-key', 'create-' + prefix);
  b.setAttribute('data-rotate-key', 'rotate-' + prefix);
  b.setAttribute('data-revoke-key', 'revoke-' + prefix);
  b.setAttribute('data-formats', '');
  b.setAttribute('data-active', '');
  b.setAttribute('data-unlocked', '1');
  return b;
}
const rowA = makeRow('A', 'Expires 2026-11-11', 'Expires in 7 days');
const rowB = makeRow('B', 'Expires 2026-11-11', 'Expires in 7 days');
const shareBtnA = makeShareBtn('A');
const shareBtnB = makeShareBtn('B');
globalThis.window = globalThis;
globalThis.__productReady = true;
globalThis.location = { origin: 'https://example.test' };
globalThis.navigator = {};
globalThis.FormData = class {
  constructor(form) { this._map = {}; }
  append(k, v) { this._map[k] = v; }
  get(k) { return Object.prototype.hasOwnProperty.call(this._map, k) ? this._map[k] : null; }
};
globalThis.document = {
  getElementById: byId,
  querySelectorAll: function (sel) {
    if (sel === 'form[data-confirm]') { return [rowA.form, rowB.form]; }
    if (sel === 'form[data-retention-form]') { return [rowA.form, rowB.form]; }
    if (sel === '.share-open') { return [shareBtnA, shareBtnB]; }
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
let fetchImpl = function () { return Promise.reject(new Error('fetch not stubbed')); };
globalThis.fetch = function (url, opts) { return fetchImpl(url, opts); };
async function flush() { for (let i = 0; i < 8; i++) { await new Promise(function (r) { setTimeout(r, 0); }); } }
async function click(el) {
  (el.listeners.click || []).forEach(function (fn) {
    fn({ preventDefault: function () {}, stopImmediatePropagation: function () {} });
  });
  await flush();
}
"""


def _run_js(scenario):
    script = None
    for candidate in re.findall(r"<script>(.*?)</script>", REPORTS, re.S):
        if "ss-confirm" in candidate and "data-retention-form" in candidate:
            script = candidate
            break
    assert script is not None, "reports.html inline script not found"
    script = script.replace("{{ csrf_token }}", "csrf-test")
    full = (_HARNESS + "\n" + script + "\n(async () => {\n  const out = {};\n"
            + scenario
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
def test_s3_browser_two_rows_present():
    """A4 browser test: with two rows present, each row's Share
    button opens the shared popup bound to ITS row (per-row origin
    state), independently of the other row."""
    out = _run_js("""
      out.rows = [shareBtnA, shareBtnB].length;
      await click(shareBtnA);
      out.afterA = byId('share-modal').style.display;
      await click(byId('share-close'));
      await click(shareBtnB);
      out.afterB = byId('share-modal').style.display;
    """)
    assert out["rows"] == 2
    assert out["afterA"] == "flex"
    assert out["afterB"] == "flex"


@pytestmark_js
def test_s3_browser_extend_updates_only_that_row():
    """A4 browser test: Extend submitted on row A updates ONLY row
    A's expiry date/pill/status (via form.closest('.card'), the
    preserved ancestor contract); row B is byte-identical after."""
    out = _run_js("""
      fetchImpl = function () {
        return Promise.resolve({ ok: true, status: 200,
          json: function () { return Promise.resolve({
            status: 'extended', expires_at: '2027-02-09T12:00:00Z',
            cost: 1, replayed: false }); } });
      };
      dispatchSubmit(rowA.form);
      out.modalShown = byId('ss-confirm').style.display;
      await click(byId('ss-confirm-yes'));
      await flush();
      out.aDate = rowA.dateEl.textContent;
      out.aPill = rowA.pillEl.textContent;
      out.aStatus = rowA.statusEl.textContent;
      out.bDate = rowB.dateEl.textContent;
      out.bPill = rowB.pillEl.textContent;
      out.bStatus = rowB.statusEl.textContent;
      out.badge = byId('credit-badge').textContent;
    """)
    assert out["modalShown"] == "flex"
    assert out["aDate"] == "Expires 2027-02-09"
    assert out["aPill"] == "Expires in 97 days"
    assert out["aStatus"] == "Retention extended."
    assert out["bDate"] == "Expires 2026-11-11"
    assert out["bPill"] == "Expires in 7 days"
    assert out["bStatus"] == ""
    assert "2 credits" in out["badge"]


@pytestmark_js
def test_s3_browser_share_switched_during_async_response():
    """A4 browser test: a share create started for row A resolves
    AFTER the popup has been switched to row B — A's per-row state
    is updated on A's button, but A's URL/message must NOT land in
    B's popup (the originating-button capture, PR #132 finding 6)."""
    out = _run_js("""
      let resolveFetch = null;
      fetchImpl = function () {
        return new Promise(function (res) {
          resolveFetch = function () {
            res({ ok: true, status: 200,
                  json: function () { return Promise.resolve({ share_url: '/s/TOKEN-A' }); } });
          };
        });
      };
      await click(shareBtnA);
      (byId('share-create').listeners.click || []).forEach(function (fn) { fn({}); });
      await click(shareBtnB);
      resolveFetch();
      await flush();
      out.aFormats = shareBtnA.getAttribute('data-formats');
      out.bFormats = shareBtnB.getAttribute('data-formats');
      out.msg = byId('share-msg').textContent;
      out.linkValue = byId('share-link').value;
      out.linkDisplay = byId('share-link-row').style.display;
    """)
    assert out["aFormats"] == "txt"
    assert out["bFormats"] == ""
    assert "TOKEN-A" not in out["msg"]
    assert out["linkValue"] == ""
    assert out["linkDisplay"] == "none"
