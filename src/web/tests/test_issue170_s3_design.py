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

Founder fidelity remediation (2026-11-10, PR #177 — the S3 items
of the design-fidelity diff land on this PR before merge):
  G1  Row actions are DIRECT controls: the primary Export button +
      format dropdown menu are gone (which also remediates the two
      Codex P2 clipping findings on c66f61cd by construction — the
      .s3-table-wrap overflow can no longer clip a menu that does
      not exist); each export is its own inline form (action URL,
      CSRF input, data-confirm byte-identical) with a uniform
      btn-ghost submit labelled "Export PDF"/"Export CSV"/
      "Export JSON"; "View" is renamed "Open"; NO "Free" tag
      (S3-R2, staged until #164 Phase C). The bare "Analysis" row
      action is renamed "Investigation Report" (2026-11-09 naming
      ruling supersedes the earlier deliberate keep; internal
      analysis-* ids/classes unchanged).
  G2  State & retention cell gains a bold status word ("Ready" /
      "Expired" — Expired exactly for redemption_only rows, the
      only expired rows this list renders) and, when the row's
      share state is active (and Share itself is not suppressed
      for the row), a share-state line whose "Turn off" control
      opens the EXISTING Share modal via the share-open mechanism
      with the same data-* attributes as the row's Share button.
      The expiry date span and "Expires in N days" pill keep
      their hooks and wording (Decision 8).
  G3  Page head: eyebrow "My Reports"; sub "Open, share, or export
      your reports. Free reports are kept for 7 days; paid
      deliverables are kept for 90 days." (the design's "delete"
      wording stays barred — no Delete anywhere).
  G4  Date cell is two lines ("Nov 04, 2026" over "12:00 UTC"),
      superseding the #144 Analyzed/Created prefix (founder
      fidelity ruling 2026-11-10); deep_dive rows stay
      distinguished by the Investigation Report kind-title.

Founder mobile-fix ruling (2026-11-10, hand-check of merged S3 on
his phone — the S3 hand-check was NOT a pass):
  M1  SUPERSEDES G1 FOR MY REPORTS ONLY, at all widths: row Export
      is ONE button with a styled dropdown (founder: "Make it a
      drop down on desktop too"). The S1 Report page keeps G1's
      direct controls. Each export keeps its own form (action URL,
      CSRF input, data-confirm byte-identical) INSIDE the dropdown
      panel; no per-format direct buttons remain in the actions
      row. Premise-changed tests: the G1 no-dropdown test is
      replaced by the mobile-fix tests below, the full-inventory
      and hooks tests now pin the toggle/panel structure, and all
      other G1-era assertions (labels, confirms, gating, absences)
      carry over unchanged.
  M2  Mobile rows reflow to a ~three-line stacked layout (line 1:
      icon + filename + severity pill, fully visible; line 2: state
      word + retention/expiry + share-state, with the date cell;
      line 3: one compact actions row — no full-width stacked
      buttons), pinned by data-s3-line hooks (1/1/2/2/3 across the
      five cells) and the mobile grid CSS. At mobile width the
      table wrap no longer clips (overflow visible), so the
      dropdown panel is not inside an overflow-clipped ancestor.
  The Batch entry card under the table (founder ruling
  2026-11-09) was checked on the base head for this slice
  (5c780b17) and is ALREADY present — no change needed.

Founder desktop addendum (2026-11-10 21:57 ET, PR #179 fold-in):
  M3  ROW-UNDER at ALL widths: the seven row actions leave the
      side ACTIONS column entirely and sit in their own full-width
      row UNDER each report's main row (a second <tr> per report
      whose single cell spans all four remaining columns). The
      thead loses the "Actions" header. Desktop and mobile share
      this one structure; on mobile the actions row IS line 3 of
      the three-line sketch (data-s3-line="3" now sits on the
      actions <tr>; main-row cells keep lines 1/2). The Date cell
      renders as two clean lines (date / time UTC) with no
      word-by-word wrap (white-space:nowrap on the cell + spans).
      Premise-changed tests (named in advance, A8): the table
      columns test (Actions column gone), the mobile stacked
      layout hooks test (actions no longer a grid area inside
      the main row; the main-row grid is two lines and the
      actions <tr> is the mobile card's lower half), the
      _row_for helper (a row segment now spans BOTH <tr>s), and
      the G2/retention state-cell slices (unchanged anchors —
      the actions cell still follows the state cell, now in the
      second <tr>). Assertion strength is kept or raised.
  M4  Codex P2 on PR #179: the export panel was right:0 with
      min-width:196px; in the row-under structure the Export
      trigger sits near the LEFT edge at all widths, so the
      right-aligned panel overhung the viewport's left edge.
      The panel now anchors to the trigger's left edge
      (left:0; right:auto) and is capped at
      max-width:calc(100vw - 24px).
  M5  Runtime interaction tests (standing rule 2026-11-10): the
      Node dropdown harness enumerates the mutation sequences
      (open A -> open B, Escape, outside click) asserting the
      DISPLAYED state (hidden + aria-expanded) after each step,
      and a structural test pins the Share control + share-state
      line to the same row's report id/keys after the move (the
      share modal JS itself is untouched apart from a guarded
      previous-sibling fallback in syncShareStateLineFor /
      updateExtendedRow, needed because closest('.card') now
      lands on the actions row first).
  M6  PR #179 Codex P2 remediation: that fallback broke the
      retention STATUS update — updateExtendedRow reassigned its
      row variable to the main row, then looked
      [data-retention-status] up there (always null; the status
      lives in the actions row next to the form), so "Retention
      extended." was never displayed. The fix keeps a separate
      actions-row reference for the status lookup (falling back
      to the main row only if the actions row has none), and the
      Node harness mock now mirrors the real split-row DOM
      (expiry in the main row, form + status in the actions-row
      sibling) so the existing extend test has teeth for it.
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
    # M3 premise change: a report's segment spans BOTH rows — the
    # main <tr class="card s3-row"> and the row-under actions
    # <tr class="card s3-actions-tr"> that follows it — up to the
    # next report's main row (the same slicing the deep-dive row
    # helpers in other test files already used).
    view_link = f'href="/reports/{report_id}" class="btn btn-ghost">Open'
    rows = html.split('<tr class="card s3-row">')
    matches = [r for r in rows if view_link in r]
    assert len(matches) == 1, report_id
    return matches[0].split("</tbody>")[0]


# --- New table structure (TEETH) --------------------------------------------


def test_s3_table_structure_and_columns():
    html = _render([_report()])
    assert '<table class="s3-table">' in html
    assert '<div class="s3-table-wrap">' in html
    head = html[html.index("<thead>"):html.index("</thead>")]
    cols = [head.index(f">{name}<") for name in
            ("Report", "Date", "Severity", "State &amp; retention")]
    assert cols == sorted(cols), cols
    # M3 premise change (founder ruling 2026-11-10 21:57): there
    # is NO Actions column — the actions live in a row under.
    assert ">Actions<" not in head
    assert html.count('<tr class="card s3-row">') == 1
    assert html.count('<tr class="card s3-actions-tr"') == 1
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
    # G3 (founder fidelity ruling 2026-11-10): eyebrow is the page
    # name (CSS uppercases it to MY REPORTS) and the sub carries
    # the design's retention sentence — now true post-#164 Phase A.
    # The design sub's "delete" wording stays barred (S3-R1/A4).
    assert '<p class="s3-eyebrow">My Reports</p>' in html
    assert html.index('class="s3-eyebrow"') < html.index(
        "<h1>My Reports</h1>")
    sub = ("Open, share, or export your reports. Free reports are "
           "kept for 7 days; paid deliverables are kept for 90 days.")
    assert f'<p class="sub">{sub}</p>' in html
    assert "Your analysis reports from the last 7 days." not in html
    assert "Manage</p>" not in html
    assert "delete" not in sub.lower()
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
    # M1 (supersedes G1 on this surface): Open + ONE Export button
    # whose dropdown panel holds the three export forms.
    assert ">Open</a>" in row
    assert ">View</a>" not in row
    assert f'action="/reports/{rid}/pdf"' in row
    assert f'action="/reports/{rid}/exports/csv"' in row
    assert f'action="/reports/{rid}/exports/json"' in row
    assert ">Export PDF</button>" in row
    assert ">Export CSV</button>" in row
    assert ">Export JSON</button>" in row
    assert row.count("data-confirm") == 4  # 3 exports + Extend
    assert row.count(f'data-confirm="{_LOCKED}"') == 3
    # Rename (2026-11-09 naming ruling): the row action is the
    # deliverable's name; the bare "Analysis" label is gone, the
    # internal analysis-open class/ids are unchanged.
    assert "analysis-open" in row
    assert ">Investigation Report</button>" in row
    assert ">Analysis</button>" not in row
    assert "share-open" in row and ">Share</button>" in row
    assert f'action="/reports/{rid}/retention"' in row
    assert ">Extend</button>" in row
    # Hooks present per row (A4 / spec parity list).
    assert row.count("data-retention-expiry-date") == 1
    assert row.count("data-retention-expiry-pill") == 1
    assert row.count("data-retention-status") == 1


def test_s3_mobilefix_single_export_button_and_menu():
    """M1 teeth (founder mobile-fix ruling 2026-11-10, superseding
    G1 on My Reports at ALL widths): each row carries exactly ONE
    Export button (the dropdown toggle, quiet btn-ghost, with
    aria-haspopup/aria-expanded) and exactly ONE dropdown panel,
    initially hidden and styled in the house system. The three
    export forms live INSIDE the panel, in PDF/CSV/JSON order,
    each with its action URL, CSRF input and locked data-confirm
    byte-identical to the direct-control era; NO per-format export
    form or submit appears in the actions row outside the panel.
    No "Free" tag is rendered (S3-R2). Fails on the base tree,
    where exports are three direct row forms and no toggle/panel
    exists at all."""
    rid = "row-m1"
    html = _render([_report(id=rid)])
    row = _row_for(html, rid)
    assert row.count("data-s3-export-btn") == 1
    assert row.count("data-s3-export-menu") == 1
    assert ('class="btn btn-ghost s3-export-btn" aria-haspopup="true" '
            'aria-expanded="false" data-s3-export-btn>Export '
            '<span class="s3-caret" aria-hidden="true">▾</span>'
            '</button>') in row
    assert '<div class="s3-export-menu" data-s3-export-menu hidden>' in row
    # Panel slice: the three export forms, in order, fully gated.
    panel = row[row.index("data-s3-export-menu"):
                row.index("</div>", row.index("data-s3-export-menu"))]
    order = [panel.index(f'action="/reports/{rid}/pdf"'),
             panel.index(f'action="/reports/{rid}/exports/csv"'),
             panel.index(f'action="/reports/{rid}/exports/json"')]
    assert order == sorted(order), order
    assert panel.count('name="csrf_token"') == 3
    assert panel.count(f'data-confirm="{_LOCKED}"') == 3
    for label in ("Export PDF", "Export CSV", "Export JSON"):
        assert (f'class="btn btn-ghost s3-export-item">{label}</button>'
                in panel), label
    # Outside the panel there are no per-format direct controls:
    # strip the panel (it ends at the wrapper's close, marked by
    # the second closing div after the panel open) and re-check.
    outside = row[:row.index('<div class="s3-export">')]
    outside += row[row.index('</div>\n        </div>'):] \
        if '</div>\n        </div>' in row else ""
    assert "Export PDF" not in outside and "s3-export-form" not in outside
    # Uniform quiet styling everywhere on the row: Open + Export
    # toggle + 3 export submits + Investigation Report + Share +
    # Extend submit = 8 quiet controls, no btn-primary.
    assert row.count("btn btn-ghost") == 8
    assert "btn-primary" not in row
    assert ">Free<" not in row and "Free</span>" not in row
    # The panel is styled in the house system (page tokens, panel
    # surface, border, radius) and positioned against its wrapper.
    inline = REPORTS[REPORTS.index("Issue #170 S3"):
                     REPORTS.index("</style>")]
    assert ".s3-export{position:relative" in inline
    assert ".s3-export-menu{position:absolute" in inline
    assert "background:var(--panel)" in inline
    assert ".s3-export-menu[hidden]{display:none}" in inline
    # M4 (Codex P2 on PR #179): the panel anchors to the trigger's
    # LEFT edge — in the row-under structure the trigger sits near
    # the left at all widths, so a right:0 panel overhung the
    # viewport's left edge and cut off the export controls — and
    # it can never exceed the viewport width.
    assert ".s3-export-menu{position:absolute;left:0;right:auto" \
        in inline
    assert "max-width:calc(100vw - 24px)" in inline
    assert ".s3-export-menu{position:absolute;right:0" not in inline


def test_s3_mobilefix_mobile_stacked_layout_hooks():
    """M2 teeth, as amended by M3 (founder ruling 2026-11-10
    21:57 — premise changed, named in advance): the three lines
    are now TWO rows. Markup: data-s3-line groups the main-row
    cells as 1 (Report, Severity) / 2 (State, Date), and line 3
    sits on the actions <tr> itself. CSS: at max-width 640px the
    main row is a grid with exactly the line-1/line-2 areas, the
    actions <tr> is the card's lower half (display:block, shared
    panel/border, no separate margin), the thead is hidden, the
    severity pill cannot wrap/clip, the filename column can
    shrink (minmax(0,1fr)), the actions row's buttons are compact
    (flex:none — NOT the full-width stacked buttons Kolby
    flagged), and the table wrap stops clipping
    (overflow:visible) so the export dropdown panel is not inside
    an overflow-clipped ancestor at mobile width."""
    rid = "row-m2"
    row = _row_for(_render([_report(id=rid)]), rid)
    assert row.count('data-s3-line="1"') == 2  # Report + Severity
    assert row.count('data-s3-line="2"') == 2  # State + Date
    assert row.count('data-s3-line="3"') == 1  # Actions <tr>
    assert 'class="s3-report-cell" data-s3-line="1"' in row
    assert 'class="s3-severity-cell" data-s3-line="1"' in row
    assert 'class="s3-state-cell" data-s3-line="2"' in row
    assert 'class="s3-date-cell" data-s3-line="2"' in row
    assert '<tr class="card s3-actions-tr" data-s3-line="3">' in row
    assert 'class="s3-actions-cell" data-s3-line="3"' not in row
    inline = REPORTS[REPORTS.index("Issue #170 S3"):
                     REPORTS.index("</style>")]
    mobile = inline[inline.rindex("@media (max-width:640px)"):]
    assert ".s3-table-wrap{overflow:visible" in mobile
    assert "display:grid" in mobile
    assert ('grid-template-areas:"report severity" "state date"'
            ) in mobile
    assert '"actions actions"' not in mobile
    assert "grid-template-columns:minmax(0,1fr) auto" in mobile
    assert ".s3-table thead{display:none}" in mobile
    assert (".s3-table tbody tr.card.s3-actions-tr{display:block"
            in mobile)
    assert ".s3-severity-cell .s3-pill{white-space:nowrap}" in mobile
    assert ".s3-actions-cell .s3-actions-row .btn{flex:none" in mobile
    assert "height:32px" in mobile
    # The clipping rule the mobile block overrides is the desktop
    # wrap's overflow-x — the override must come after it in source.
    assert inline.index("overflow-x:auto") < \
        mobile.index("overflow:visible") + inline.rindex(
            "@media (max-width:640px)")


def test_s3_rowunder_actions_row_structure():
    """M3 teeth (founder ruling 2026-11-10 21:57, all widths): the
    seven row actions are NOT in the main row at all — the main
    <tr> carries only the four content cells — and sit in their
    own full-width row under it: a second <tr> whose single cell
    spans all four columns (colspan="4") and carries the actions
    container. Order inside the actions row is Open / Export /
    Investigation Report / Share / Extend, every control quiet
    btn-ghost. The desktop CSS gives the actions row's spanning
    cell the group separator (the main row's cells carry none).
    Fails on the pre-addendum tree (e632936c): the actions cell
    sits inside the main row and the thead has an Actions column.
    """
    rid = "row-under"
    html = _render([_report(id=rid)])
    assert ">Actions<" not in html
    main = html[html.index('<tr class="card s3-row">'):]
    main = main[:main.index("</tr>")]
    for absent in (">Open</a>", "s3-export", ">Share</button>",
                   "/retention", 'class="s3-actions-cell"'):
        assert absent not in main, absent
    assert main.count("<td") == 4
    row = _row_for(html, rid)
    assert '<tr class="card s3-actions-tr" data-s3-line="3">' in row
    assert '<td class="s3-actions-cell" colspan="4">' in row
    actions = row[row.index('<tr class="card s3-actions-tr"'):]
    order = [actions.index(">Open</a>"),
             actions.index("data-s3-export-btn"),
             actions.index(">Investigation Report</button>"),
             actions.index(">Share</button>"),
             actions.index(">Extend</button>")]
    assert order == sorted(order), order
    assert actions.count("btn btn-ghost") == \
        row.count("btn btn-ghost")  # all quiet controls are here
    inline = REPORTS[REPORTS.index("Issue #170 S3"):
                     REPORTS.index("</style>")]
    desktop = inline[:inline.rindex("@media (max-width:640px)")]
    assert ".s3-table tbody tr.s3-row td{border-bottom:none}" \
        in desktop
    assert (".s3-table tbody tr.s3-actions-tr td{padding:2px 16px "
            "16px;border-bottom:1px solid var(--border)}") in desktop


def test_s3_rowunder_share_wiring_same_row():
    """M5(d) structural gate: after the row-under move, the Share
    control in the actions row and the Turn off control inside
    the .s3-share-state line (state cell, main row) are still
    wired to the SAME row's report — both share-open controls
    carry this row's data-report and byte-identical create /
    rotate / revoke keys, and no other row's id leaks in. The
    share modal JS itself is untouched by the move (apart from
    the guarded sibling fallback), so rendered-page structure is
    the assertion surface for the wiring."""
    rid_a, rid_b = "row-share-a", "row-share-b"
    html = _render([
        _report(id=rid_a, share_active=True, share_formats=["txt"],
                share_create_key="create-a",
                share_rotate_key="rotate-a",
                share_revoke_key="revoke-a"),
        _report(id=rid_b, share_active=True, share_formats=["txt"],
                share_create_key="create-b",
                share_rotate_key="rotate-b",
                share_revoke_key="revoke-b"),
    ])
    for rid, suffix in ((rid_a, "a"), (rid_b, "b")):
        row = _row_for(html, rid)
        # State line lives in the MAIN row; Share in the row under.
        state = row[:row.index('<tr class="card s3-actions-tr"')]
        actions = row[row.index('<tr class="card s3-actions-tr"'):]
        assert 'class="s3-share-state"' in state
        assert ">Turn off</button>" in state
        assert ">Share</button>" in actions
        attrs = re.findall(
            r'class="btn btn-ghost share-open"([^>]*)>', row)
        assert len(attrs) == 2, attrs
        assert attrs[0] == attrs[1], attrs
        for attr in (f'data-report="{rid}"',
                     f'data-create-key="create-{suffix}"',
                     f'data-rotate-key="rotate-{suffix}"',
                     f'data-revoke-key="revoke-{suffix}"'):
            assert attr in attrs[0], attr
        other = "b" if suffix == "a" else "a"
        assert f"create-{other}" not in row


def test_s3_g2_status_word_and_share_state_line():
    """G2 teeth: the State cell leads with a bold status word —
    "Ready" for a live row, "Expired" for a redemption_only row —
    while the Decision 8 expiry date/pill keep hooks and wording.
    The share-state line appears ONLY when the row's share state
    is active, and its Turn off control is a second share-open
    carrying the SAME data-* attributes as the row's Share button
    (it opens the existing Share modal — no new endpoint/flow)."""
    rid = "row-g2"
    row = _row_for(_render([_report(id=rid)]), rid)
    state = row[row.index('class="s3-state-cell"'):
                row.index('class="s3-actions-cell"')]
    assert '<strong class="s3-status-word">Ready</strong>' in state
    assert "Expired</strong>" not in state
    assert "Expires 2026-11-11" in state
    assert "Expires in 7 days" in state
    assert "Link sharing on" not in state  # share inactive

    expired = _row_for(_render([_report(
        id="row-g2x", redemption_only=True)]), "row-g2x")
    xstate = expired[expired.index('class="s3-state-cell"'):
                     expired.index('class="s3-actions-cell"')]
    assert '<strong class="s3-status-word">Expired</strong>' in xstate
    assert "Redemption only — this report has expired" in xstate

    shared = _row_for(_render([_report(
        id="row-g2s", share_active=True, share_formats=["txt"])]),
        "row-g2s")
    sstate = shared[shared.index('class="s3-state-cell"'):
                    shared.index('class="s3-actions-cell"')]
    assert ("Link sharing on — anyone with the link can view"
            in sstate)
    assert ">Turn off</button>" in sstate
    # Two share-open controls on the row (Share + Turn off), with
    # byte-identical data-* attribute sets.
    assert shared.count("share-open") == 2
    attrs = re.findall(r'class="btn btn-ghost share-open"([^>]*)>',
                       shared)
    assert len(attrs) == 2 and attrs[0] == attrs[1], attrs
    assert 'data-formats="txt"' in attrs[0]
    assert 'data-active="1"' in attrs[0]


def test_s3_g4_date_cell_two_lines():
    """G4 teeth: the Date cell is two lines — "Nov 04, 2026" over
    "12:00 UTC" — for every row kind. The #144 Analyzed/Created
    prefix is superseded (founder fidelity ruling 2026-11-10);
    deep_dive rows stay distinguished by the kind-title."""
    for overrides in ({}, {"type": "deep_dive",
                           "filename": "deep.log",
                           "analysis_eligible": False}):
        rid = "row-g4"
        row = _row_for(_render([_report(id=rid, **overrides)]), rid)
        cell = row[row.index('class="s3-date-cell"'):
                   row.index('class="s3-severity-cell"')]
        assert '<span class="s3-date-line">Nov 04, 2026</span>' in cell
        assert '<span class="s3-date-sub">12:00 UTC</span>' in cell
        assert "Analyzed" not in cell and "Created" not in cell
        assert "2026-11-04 12:00" not in cell
    # M3 date premise (founder addendum 2026-11-10 21:57): the two
    # lines must not wrap word-by-word in a narrow column — the
    # cell and both spans are white-space:nowrap at ALL widths
    # (the rules live outside the mobile media block).
    inline = REPORTS[REPORTS.index("Issue #170 S3"):
                     REPORTS.index("</style>")]
    desktop = inline[:inline.rindex("@media (max-width:640px)")]
    assert ".s3-date-cell{white-space:nowrap}" in desktop
    assert ".s3-date-line{display:block;white-space:nowrap}" in desktop
    assert "white-space:nowrap" in desktop.split(
        ".s3-date-sub{")[1].split("}")[0]


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
    """A4 absence gate: deep_dive rows keep Open + direct Exports
    (all formats) but have NO Share and NO Extend (both routes 404
    for them) and carry the 'Investigation Report' kind title.
    G4: the date cell is the two-line date/time with no
    Analyzed/Created prefix (the #144 prefix is superseded by the
    founder fidelity ruling 2026-11-10; the kind title is what
    distinguishes these rows)."""
    rid = "row-deep"
    row = _row_for(_render([_report(
        id=rid, type="deep_dive", filename="deep-source.log",
        analysis_eligible=False)]), rid)
    assert '<div class="kind-title">Investigation Report</div>' in row
    assert row.index("Investigation Report") < row.index("deep-source.log")
    assert '<span class="s3-date-line">Nov 04, 2026</span>' in row
    assert '<span class="s3-date-sub">12:00 UTC</span>' in row
    assert "Analyzed" not in row and "Created" not in row
    assert 'action="/reports/row-deep/pdf"' in row
    assert 'action="/reports/row-deep/exports/csv"' in row
    assert ">Export PDF</button>" in row
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
           "Investigation Report</a>" in done
    assert ">Analysis</a>" not in done
    assert "analysis-open" not in done
    todo = _row_for(_render([_report(id="row-todo")]), "row-todo")
    assert "analysis-open" in todo
    assert 'data-report="row-todo"' in todo
    assert 'data-eligible="1"' in todo
    assert 'data-deadline="2026-12-11"' in todo


def test_s3_redemption_only_row_suppressions():
    """Gate: redemption-only rows keep Open + Investigation Report
    (the redeem path) and suppress Export/Share/Extend (they would
    410), with the redemption label and the G2 "Expired" status
    word in the State cell."""
    rid = "row-redeem"
    row = _row_for(_render([_report(id=rid, redemption_only=True)]), rid)
    assert "Redemption only — this report has expired" in row
    assert '<strong class="s3-status-word">Expired</strong>' in row
    assert "/pdf" not in row and "Export PDF" not in row
    assert "share-open" not in row
    assert "Extend" not in row
    assert "analysis-open" in row
    assert ">Investigation Report</button>" in row


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
    the modal actions, and the JS result messages. Founder ruling
    2026-11-10 extends the sweep to the row action itself: the
    bare "Analysis" action label is renamed "Investigation Report"
    (both the link and the analysis-open button); only internal
    identifiers (analysis-open, analysis-*) keep the word. Teeth:
    the base template carries all five retired-name strings, so
    this fails on base."""
    assert "Analysis Report" not in REPORTS
    assert "Investigation Brief" not in REPORTS
    assert '<div class="kind-title">Investigation Report</div>' in REPORTS
    assert ">View Investigation Report</a>" in REPORTS
    assert ">Generate Investigation Report</button>" in REPORTS
    assert "'Investigation Report ready.'" in REPORTS
    assert REPORTS.count("Investigation Report generation failed.") == 2
    assert ">Analysis</button>" not in REPORTS
    assert ">Analysis</a>" not in REPORTS
    assert ">Investigation Report</button>" in REPORTS
    assert ">Investigation Report</a>" in REPORTS


def test_s3_hooks_and_confirm_texts_verbatim():
    """Gate: every JS hook / data attribute carried over by name,
    with byte-identical confirm texts and per-row keys."""
    rid = "row-hooks"
    html = _render([_report(id=rid)])
    row = _row_for(html, rid)
    # M1: the old data-menu hook stays gone; the new toggle carries
    # aria-haspopup exactly once (its own hook, data-s3-export-btn).
    assert "data-menu" not in row
    assert row.count('aria-haspopup="true"') == 1
    assert row.count("data-s3-export-btn") == 1
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
    assert '<strong class="s3-status-word">Ready</strong>' in state
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


# --- Mobile-fix dropdown behaviour (Node harness, separate script) ----------

pytestmark_export_js = pytest.mark.skipif(
    shutil.which("node") is None, reason="node required for template JS tests")

_EXPORT_HARNESS = r"""
'use strict';
class El {
  constructor(name) {
    this.name = name; this.hidden = true; this.attrs = {};
    this.listeners = {};
  }
  addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
}
function makeRow(prefix) {
  const menu = new El(prefix + '-menu'); menu.hidden = true;
  const btn = new El(prefix + '-btn'); btn.setAttribute('aria-expanded', 'false');
  const wrap = new El(prefix + '-wrap');
  wrap.querySelector = function (sel) { return sel === '[data-s3-export-menu]' ? menu : null; };
  btn.closest = function (sel) { return sel === '.s3-export' ? wrap : null; };
  return { btn: btn, menu: menu, wrap: wrap };
}
const rowA = makeRow('A'); const rowB = makeRow('B');
const docListeners = {};
globalThis.document = {
  querySelectorAll: function (sel) {
    if (sel === '[data-s3-export-menu]') { return [rowA.menu, rowB.menu]; }
    if (sel === '[data-s3-export-btn]') { return [rowA.btn, rowB.btn]; }
    return [];
  },
  addEventListener: function (ev, fn) { docListeners[ev] = fn; },
};
async function click(el) {
  (el.listeners.click || []).forEach(function (fn) { fn({}); });
}
"""


def _run_export_js(scenario):
    script = None
    for candidate in re.findall(r"<script>(.*?)</script>", REPORTS, re.S):
        if "data-s3-export-btn" in candidate and "s3CloseMenus" in candidate:
            script = candidate
            break
    assert script is not None, "reports.html export dropdown script not found"
    full = (_EXPORT_HARNESS + "\n" + script + "\n(async () => {\n"
            "  const out = {};\n" + scenario
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


@pytestmark_export_js
def test_s3_mobilefix_export_dropdown_toggle_behaviour():
    """M1 behaviour teeth: the Export button toggles ONLY its own
    row's panel (hidden + aria-expanded), opening a second row's
    panel closes the first, re-clicking closes its own, and an
    outside document click closes all. Fails on the base tree —
    the dropdown script does not exist there, so the extractor
    assertion fires before any behaviour is checked."""
    out = _run_export_js("""
      await click(rowA.btn);
      out.aOpenHidden = rowA.menu.hidden;
      out.aOpenAria = rowA.btn.getAttribute('aria-expanded');
      await click(rowB.btn);
      out.afterB_AHidden = rowA.menu.hidden;
      out.afterB_AAria = rowA.btn.getAttribute('aria-expanded');
      out.afterB_BHidden = rowB.menu.hidden;
      out.afterB_BAria = rowB.btn.getAttribute('aria-expanded');
      await click(rowB.btn);
      out.bReclosedHidden = rowB.menu.hidden;
      out.bReclosedAria = rowB.btn.getAttribute('aria-expanded');
      await click(rowA.btn);
      docListeners.click({ target: {} });
      out.outsideAHidden = rowA.menu.hidden;
      out.outsideAAria = rowA.btn.getAttribute('aria-expanded');
    """)
    assert out["aOpenHidden"] is False
    assert out["aOpenAria"] == "true"
    assert out["afterB_AHidden"] is True
    assert out["afterB_AAria"] == "false"
    assert out["afterB_BHidden"] is False
    assert out["afterB_BAria"] == "true"
    assert out["bReclosedHidden"] is True
    assert out["bReclosedAria"] == "false"
    assert out["outsideAHidden"] is True
    assert out["outsideAAria"] == "false"


@pytestmark_export_js
def test_s3_mobilefix_export_dropdown_runtime_sequences():
    """M5 runtime sequences (standing rule 2026-11-10 — displayed
    state asserted after EACH mutation, DOM-level, not page
    contract): (a) open Export on row A, then open Export on
    row B -> A's panel hidden + A's aria-expanded="false", B's
    open + "true"; (b) Escape closes the open panel and resets
    aria-expanded; (c) an outside click closes it and resets
    aria-expanded. Runs against the real inline dropdown script
    extracted from reports.html, in the row-under structure."""
    out = _run_export_js("""
      // (a) A, then B through the second control sharing state.
      await click(rowA.btn);
      out.a1Hidden = rowA.menu.hidden;
      out.a1Aria = rowA.btn.getAttribute('aria-expanded');
      await click(rowB.btn);
      out.aAHidden = rowA.menu.hidden;
      out.aAAria = rowA.btn.getAttribute('aria-expanded');
      out.aBHidden = rowB.menu.hidden;
      out.aBAria = rowB.btn.getAttribute('aria-expanded');
      // (b) Escape closes B and resets its aria-expanded.
      docListeners.keydown({ key: 'Escape' });
      out.bBHidden = rowB.menu.hidden;
      out.bBAria = rowB.btn.getAttribute('aria-expanded');
      out.bAHidden = rowA.menu.hidden;
      out.bAAria = rowA.btn.getAttribute('aria-expanded');
      // (c) Reopen A, then an outside click closes it.
      await click(rowA.btn);
      out.cPreHidden = rowA.menu.hidden;
      docListeners.click({ target: {} });
      out.cAHidden = rowA.menu.hidden;
      out.cAAria = rowA.btn.getAttribute('aria-expanded');
    """)
    assert out["a1Hidden"] is False and out["a1Aria"] == "true"
    assert out["aAHidden"] is True and out["aAAria"] == "false"
    assert out["aBHidden"] is False and out["aBAria"] == "true"
    assert out["bBHidden"] is True and out["bBAria"] == "false"
    assert out["bAHidden"] is True and out["bAAria"] == "false"
    assert out["cPreHidden"] is False
    assert out["cAHidden"] is True and out["cAAria"] == "false"


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
    this.className = ''; this.children = [];
  }
  appendChild(child) { this.children.push(child); return child; }
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
  // PR #179 Codex P2 fixture: mirror the REAL row-under DOM — the
  // expiry date/pill live in the MAIN row, while the retention
  // form and its [data-retention-status] element live in a
  // separate ACTIONS row (.card) whose previousElementSibling is
  // the main row and whose closest('.card') is itself. The old
  // mock placed all three elements in one row, which hid the bug
  // where updateExtendedRow fell back to the main row and then
  // looked the status element up there (always null).
  const mainRowEl = new El(prefix + '-main-row');
  mainRowEl.querySelector = function (sel) {
    if (sel === '[data-retention-expiry-date]') { return dateEl; }
    if (sel === '[data-retention-expiry-pill]') { return pillEl; }
    return null;
  };
  const rowEl = new El(prefix + '-row');
  rowEl.previousElementSibling = mainRowEl;
  rowEl.querySelector = function (sel) {
    if (sel === '[data-retention-status]') { return statusEl; }
    return null;
  };
  const btn = { disabled: false };
  const form = new El(prefix + '-form');
  form.action = '/reports/' + prefix + '/retention';
  form._row = rowEl;
  form._mainRow = mainRowEl;
  form.getAttribute = function (k) {
    if (k === 'data-confirm') { return "Extend this report's retention by 90 days for 1 credit?"; }
    return El.prototype.getAttribute.call(this, k);
  };
  form.querySelector = function (sel) { return sel.indexOf('submit') !== -1 ? btn : null; };
  form.closest = function (sel) { return sel === '.card' ? rowEl : null; };
  form.requestSubmit = function () { dispatchSubmit(form); };
  return { form: form, rowEl: rowEl, mainRowEl: mainRowEl,
           actionsRowEl: rowEl, dateEl: dateEl, pillEl: pillEl,
           statusEl: statusEl, btn: btn };
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
const sharePeer1 = makeShareBtn('peer1');
sharePeer1.setAttribute('data-report', 'P');
sharePeer1.setAttribute('data-create-key', 'create-P');
sharePeer1.setAttribute('data-rotate-key', 'rotate-P');
sharePeer1.setAttribute('data-revoke-key', 'revoke-P');
const sharePeer2 = makeShareBtn('peer2');
sharePeer2.setAttribute('data-report', 'P');
sharePeer2.setAttribute('data-create-key', 'create-P');
sharePeer2.setAttribute('data-rotate-key', 'rotate-P');
sharePeer2.setAttribute('data-revoke-key', 'revoke-P');
// PR #177 P2 fixtures: a fake table row per report so the
// share-state line sync can be driven. Report P was share-active
// at page load, so the server rendered its .s3-share-state line
// inside the row's .s3-state-cell and BOTH peer controls live in
// that row (closest('.card') -> the row). Report Q was unshared
// at page load: its row has a state cell but NO line element.
function makeShareRow(prefix, withLine) {
  const stateCell = new El(prefix + '-state-cell');
  const line = withLine ? new El(prefix + '-share-line') : null;
  if (line) {
    line.className = 's3-share-state'; line.style.display = '';
    stateCell.children.push(line);
  }
  const row = new El(prefix + '-card');
  row.querySelector = function (sel) {
    if (sel === '.s3-state-cell') { return stateCell; }
    if (sel === '.s3-share-state') {
      if (line) { return line; }
      for (const child of stateCell.children) {
        if (child.className === 's3-share-state') { return child; }
      }
      return null;
    }
    return null;
  };
  return { row: row, stateCell: stateCell, line: line };
}
const shareRowP = makeShareRow('P', true);
sharePeer1.closest = function (sel) { return sel === '.card' ? shareRowP.row : null; };
sharePeer2.closest = function (sel) { return sel === '.card' ? shareRowP.row : null; };
const shareRowQ = makeShareRow('Q', false);
const shareQ1 = makeShareBtn('Q1');
shareQ1.setAttribute('data-report', 'Q');
shareQ1.setAttribute('data-create-key', 'create-Q');
shareQ1.setAttribute('data-rotate-key', 'rotate-Q');
shareQ1.setAttribute('data-revoke-key', 'revoke-Q');
shareQ1.closest = function (sel) { return sel === '.card' ? shareRowQ.row : null; };
const shareQ2 = makeShareBtn('Q2');
shareQ2.setAttribute('data-report', 'Q');
shareQ2.setAttribute('data-create-key', 'create-Q');
shareQ2.setAttribute('data-rotate-key', 'rotate-Q');
shareQ2.setAttribute('data-revoke-key', 'revoke-Q');
shareQ2.closest = function (sel) { return sel === '.card' ? shareRowQ.row : null; };
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
    if (sel === '.share-open') { return [shareBtnA, shareBtnB, sharePeer1, sharePeer2, shareQ1, shareQ2]; }
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
  createElement: function (tag) { return new El('created-' + tag); },
  createTextNode: function (t) {
    const n = new El('text-node'); n.textContent = t; return n;
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
    """A4 browser test + PR #179 Codex P2 regression: Extend
    submitted on row A updates ONLY row A's expiry date/pill (on
    the MAIN row, reached via the actions row's
    previousElementSibling fallback) AND its retention status
    (on the ACTIONS row, where the form lives — text set to
    "Retention extended." and display cleared so it is shown /
    announced); row B is byte-identical after. The harness mock
    mirrors the real split-row DOM, so this fails on the pre-fix
    template: the fallen-back main-row status lookup returned
    null and the status was never displayed."""
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
      out.aStatusDisplay = rowA.statusEl.style.display;
      out.bDate = rowB.dateEl.textContent;
      out.bPill = rowB.pillEl.textContent;
      out.bStatus = rowB.statusEl.textContent;
      out.bStatusDisplay = rowB.statusEl.style.display;
      out.badge = byId('credit-badge').textContent;
    """)
    assert out["modalShown"] == "flex"
    assert out["aDate"] == "Expires 2027-02-09"
    assert out["aPill"] == "Expires in 97 days"
    assert out["aStatus"] == "Retention extended."
    assert out["aStatusDisplay"] == ""
    assert out["bDate"] == "Expires 2026-11-11"
    assert out["bPill"] == "Expires in 7 days"
    assert out["bStatus"] == ""
    assert out["bStatusDisplay"] == "none"
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


@pytestmark_js
def test_s3_browser_share_peer_controls_sync_keys_and_formats():
    """PR #177 P1 regression: TWO share-open controls for the SAME
    report (row Share + S3-G2 Turn off) must mirror share state.
    Revoke via control 1 consumes its revoke key and freshens it;
    the peer must receive the SAME fresh key, otherwise a later
    revoke via the peer replays the consumed key, the server's
    prior-replay branch returns revoked without revoking the new
    token, and the client reports success while the new link stays
    live. This test drives revoke(1) -> create -> revoke(2) and
    asserts peer key/format/active sync at each step. It fails on
    the pre-fix reports.html (peer keeps the consumed key)."""
    out = _run_js("""
      const calls = [];
      fetchImpl = function (url, opts) {
        const key = opts && opts.body ? opts.body.get('idempotency_key') : null;
        calls.push({ url: url, key: key });
        if (url.indexOf('/share/revoke') !== -1) {
          return Promise.resolve({ ok: true, status: 200,
            json: function () { return Promise.resolve({ status: 'revoked' }); } });
        }
        if (url.indexOf('/share') !== -1) {
          return Promise.resolve({ ok: true, status: 200,
            json: function () { return Promise.resolve({ share_url: '/s/NEWTOKEN' }); } });
        }
        return Promise.reject(new Error('unexpected url ' + url));
      };
      // Sharing is on for report P on both controls (server render).
      [sharePeer1, sharePeer2].forEach(function (b) {
        b.setAttribute('data-formats', 'txt');
        b.setAttribute('data-active', '1');
      });
      out.initialRevoke = sharePeer1.getAttribute('data-revoke-key');
      // (1) Revoke via control 1.
      await click(sharePeer1);
      await click(byId('share-revoke'));
      out.revokeCalls1 = calls.filter(function (c) { return c.url.indexOf('/revoke') !== -1; });
      out.afterRevoke1Peer1Key = sharePeer1.getAttribute('data-revoke-key');
      out.afterRevoke1Peer2Key = sharePeer2.getAttribute('data-revoke-key');
      out.afterRevoke1Peer1Formats = sharePeer1.getAttribute('data-formats');
      out.afterRevoke1Peer2Formats = sharePeer2.getAttribute('data-formats');
      out.afterRevoke1Peer1Active = sharePeer1.getAttribute('data-active');
      out.afterRevoke1Peer2Active = sharePeer2.getAttribute('data-active');
      // (2) Create a new link via control 1, then revoke via control 2.
      await click(sharePeer1);
      await click(byId('share-create'));
      out.afterCreatePeer1Formats = sharePeer1.getAttribute('data-formats');
      out.afterCreatePeer2Formats = sharePeer2.getAttribute('data-formats');
      out.afterCreatePeer1Active = sharePeer1.getAttribute('data-active');
      out.afterCreatePeer2Active = sharePeer2.getAttribute('data-active');
      out.afterCreatePeer1CreateKey = sharePeer1.getAttribute('data-create-key');
      out.afterCreatePeer2CreateKey = sharePeer2.getAttribute('data-create-key');
      await click(sharePeer2);
      await click(byId('share-revoke'));
      out.calls = calls;
      out.revokeCalls = calls.filter(function (c) { return c.url.indexOf('/revoke') !== -1; });
      out.finalPeer1Formats = sharePeer1.getAttribute('data-formats');
      out.finalPeer2Formats = sharePeer2.getAttribute('data-formats');
      out.finalPeer1Active = sharePeer1.getAttribute('data-active');
      out.finalPeer2Active = sharePeer2.getAttribute('data-active');
      out.finalPeer1RevokeKey = sharePeer1.getAttribute('data-revoke-key');
      out.finalPeer2RevokeKey = sharePeer2.getAttribute('data-revoke-key');
    """)
    # (1) Both controls' revoke keys freshened together, to the same value.
    assert out["initialRevoke"] == "revoke-P"
    assert out["revokeCalls1"][0]["key"] == "revoke-P"
    assert out["afterRevoke1Peer1Key"] != "revoke-P"
    assert out["afterRevoke1Peer2Key"] != "revoke-P"
    assert out["afterRevoke1Peer1Key"] == out["afterRevoke1Peer2Key"]
    assert out["afterRevoke1Peer1Formats"] == ""
    assert out["afterRevoke1Peer2Formats"] == ""
    assert out["afterRevoke1Peer1Active"] == ""
    assert out["afterRevoke1Peer2Active"] == ""
    # Create syncs formats/active (and its fresh create key) to both peers.
    assert out["afterCreatePeer1Formats"] == "txt"
    assert out["afterCreatePeer2Formats"] == "txt"
    assert out["afterCreatePeer1Active"] == "1"
    assert out["afterCreatePeer2Active"] == "1"
    assert out["afterCreatePeer1CreateKey"] != "create-P"
    assert out["afterCreatePeer2CreateKey"] == out["afterCreatePeer1CreateKey"]
    # (2) Revoke via the peer uses the FRESH key, not the consumed one.
    assert len(out["revokeCalls"]) == 2
    assert out["revokeCalls"][1]["key"] == out["afterRevoke1Peer2Key"]
    assert out["revokeCalls"][1]["key"] != "revoke-P"
    assert out["finalPeer1Formats"] == ""
    assert out["finalPeer2Formats"] == ""
    assert out["finalPeer1Active"] == ""
    assert out["finalPeer2Active"] == ""
    assert out["finalPeer1RevokeKey"] == out["finalPeer2RevokeKey"]
    assert out["finalPeer1RevokeKey"] != out["afterRevoke1Peer1Key"]


@pytestmark_js
def test_s3_browser_share_state_line_syncs_after_mutations():
    """PR #177 P2 regression (Codex thread r4527852735): the
    server-rendered .s3-share-state line must sync with share
    mutations without a reload. Scenario P (line rendered, sharing
    on): revoking the last active format HIDES the line; a later
    create shows it again. Scenario Q (no line rendered, sharing
    off): the first successful create BUILDS the line in the state
    cell, matching the server render (class, verbatim text, Turn
    off share-open button carrying the row's post-sync data-*),
    and clicking that built Turn off button opens the share modal.
    Fails on the pre-fix reports.html: no line sync exists, so the
    line stays visible after the last revoke and is never built
    on the first create."""
    out = _run_js("""
      fetchImpl = function (url, opts) {
        if (url.indexOf('/share/revoke') !== -1) {
          return Promise.resolve({ ok: true, status: 200,
            json: function () { return Promise.resolve({ status: 'revoked' }); } });
        }
        if (url.indexOf('/share') !== -1) {
          return Promise.resolve({ ok: true, status: 200,
            json: function () { return Promise.resolve({ share_url: '/s/NEWTOKEN' }); } });
        }
        return Promise.reject(new Error('unexpected url ' + url));
      };
      // --- Scenario P: line present, sharing on (server render).
      [sharePeer1, sharePeer2].forEach(function (b) {
        b.setAttribute('data-formats', 'txt');
        b.setAttribute('data-active', '1');
      });
      out.pInitialDisplay = shareRowP.line.style.display;
      await click(sharePeer1);
      await click(byId('share-revoke'));
      out.pAfterRevokeDisplay = shareRowP.line.style.display;
      out.pAfterRevokeFormats = sharePeer1.getAttribute('data-formats');
      out.pAfterRevokeActive = sharePeer1.getAttribute('data-active');
      await click(sharePeer1);
      await click(byId('share-create'));
      out.pAfterCreateDisplay = shareRowP.line.style.display;
      out.pAfterCreateFormats = sharePeer1.getAttribute('data-formats');
      // --- Scenario Q: no line, sharing off; first create builds it.
      out.qCellChildrenBefore = shareRowQ.stateCell.children.length;
      await click(shareQ1);
      await click(byId('share-create'));
      out.qCellChildrenAfter = shareRowQ.stateCell.children.length;
      const builtLine = shareRowQ.stateCell.children.length
        ? shareRowQ.stateCell.children[shareRowQ.stateCell.children.length - 1]
        : null;
      out.qLineClass = builtLine ? builtLine.className : null;
      out.qLineText = (builtLine && builtLine.children.length)
        ? builtLine.children[0].textContent : null;
      let turnOffBtn = null;
      if (builtLine) {
        for (const child of builtLine.children) {
          if (child.textContent === 'Turn off') { turnOffBtn = child; }
        }
      }
      out.qTurnOffClass = turnOffBtn ? turnOffBtn.className : null;
      out.qTurnOffReport = turnOffBtn ? turnOffBtn.getAttribute('data-report') : null;
      out.qTurnOffFormats = turnOffBtn ? turnOffBtn.getAttribute('data-formats') : null;
      await click(byId('share-close'));
      out.qModalBeforeTurnOff = byId('share-modal').style.display;
      if (turnOffBtn) { await click(turnOffBtn); }
      out.qModalAfterTurnOff = byId('share-modal').style.display;
    """)
    # Scenario P: hide on last revoke, show again on create.
    assert out["pInitialDisplay"] == ""
    assert out["pAfterRevokeDisplay"] == "none"
    assert out["pAfterRevokeFormats"] == ""
    assert out["pAfterRevokeActive"] == ""
    assert out["pAfterCreateDisplay"] == ""
    assert out["pAfterCreateFormats"] == "txt"
    # Scenario Q: the line is built on first create, server-shaped.
    assert out["qCellChildrenBefore"] == 0
    assert out["qCellChildrenAfter"] == 1
    assert out["qLineClass"] == "s3-share-state"
    assert out["qLineText"] == \
        "Link sharing on — anyone with the link can view "
    assert out["qTurnOffClass"] == "btn btn-ghost share-open"
    assert out["qTurnOffReport"] == "Q"
    assert out["qTurnOffFormats"] == "txt"
    assert out["qModalBeforeTurnOff"] == "none"
    assert out["qModalAfterTurnOff"] == "flex"
