"""Issue #142a — post-gate polish, report surfaces (page-contract tests).

Pins the three fixes from the #142 spec
(workspace/goals/goodfolkhq-engineering-governance/files/
stacksift-142-spec-2026-11-18.md):

1. ONE shared modal system: .btn-small has a base rule in the shared
   stylesheet (it previously existed only inside settings.html's own
   <style> block, so modal buttons on the Report page rendered as
   browser defaults), and every popup instance on the style.css
   pages uses the shared .modal-overlay / .modal-card classes with a
   gold-primary / ghost button hierarchy.
2. My Reports: the Open control is removed; the report name is the
   row's link and the card itself navigates (JS handler pinned here;
   executed-DOM behavior is in test_issue142a_browser.py).
3. Titles: the My Reports name wraps at mobile widths instead of
   truncating, and the Report page title no longer uses
   word-break: break-all.

Every test here fails on the pre-#142a tree (teeth) except where a
docstring says otherwise.
"""
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
CSS = (APP / "static" / "style.css").read_text()
REPORT = (APP / "templates" / "report.html").read_text()
REPORTS = (APP / "templates" / "reports.html").read_text()
REDEMPTION = (APP / "templates" / "redemption_only.html").read_text()
AUTH_SCRIPT = (APP / "templates" / "auth_form_script.html").read_text()


# --- 1. Shared modal system -------------------------------------------------


def test_btn_small_base_rule_lives_in_shared_stylesheet():
    """The root cause of the founder's 2026-11-04 screenshot: btn-small
    was defined only inside settings.html. The shared sheet must carry
    the base rule plus the modal hierarchy compounds."""
    assert ".btn-small { padding: 0.35rem 0.75rem;" in CSS
    assert ".btn-small.btn-primary {" in CSS
    assert ".btn-small.btn-ghost {" in CSS


def test_shared_modal_classes_defined_once_in_shared_stylesheet():
    assert ".modal-overlay { position: fixed; inset: 0;" in CSS
    assert ".modal-overlay-top {" in CSS
    assert ".modal-card { background: var(--panel);" in CSS
    assert ".modal-btn-block {" in CSS


def test_shared_modal_block_sits_outside_every_170_scoped_slice():
    """PR #194 remediation: the #170 scope tests slice style.css by
    section markers (S3->S2, S2->S4, S4->EOF). The unscoped shared
    modal block must sit BEFORE the first scoped block, or it lands
    inside a neighbour's slice and fails its scope guard — exactly
    the CI failure on 214935f (test_s2_css_block_is_analyze_scoped:
    unscoped selector '.btn-small' in the S2 slice)."""
    assert CSS.index("Issue #142a") < CSS.index("Issue #170 S1")


def test_reports_page_defines_the_shared_modal_classes_it_uses():
    """PR #194 remediation (Codex P2): reports.html is self-styled
    (no style.css link) but includes auth_form_script.html, whose
    success/error modals use the shared classes. The page's own
    sheet must define every one of them, or a PDF export failure
    renders in-flow instead of as a fixed overlay."""
    for needle in (".modal-overlay{position:fixed;inset:0;",
                   ".modal-overlay-top{",
                   ".modal-title{",
                   ".modal-btn-block{display:block;",
                   ".modal-lead{"):
        assert needle in REPORTS, needle


def test_report_page_modals_use_shared_classes_not_inline_styles():
    assert 'id="analysis-modal" class="modal-overlay"' in REPORT
    assert 'id="share-modal" class="modal-overlay"' in REPORT
    assert REPORT.count('<div class="modal-card">') == 2
    # No inline-styled overlay or card remains on the page.
    assert "position:fixed" not in REPORT
    assert "background:var(--panel,#10254a)" not in REPORT


def test_report_page_modal_button_hierarchy():
    """Confirming actions are the gold primary; dismissals are ghost."""
    assert 'class="btn-small btn-primary" id="analysis-confirm"' in REPORT
    assert 'class="btn-small btn-ghost" id="analysis-close"' in REPORT
    assert 'class="btn-small btn-primary" id="share-create"' in REPORT
    assert 'class="btn-small btn-ghost" id="share-close"' in REPORT
    assert 'class="btn-small btn-ghost" id="share-revoke"' in REPORT


def test_auth_script_modals_use_shared_classes_not_csstext():
    """The JS-built success/error modals take the shared classes; no
    hand-rolled fixed-overlay cssText survives in the script."""
    assert "position:fixed" not in AUTH_SCRIPT
    assert "modal-overlay modal-overlay-top" in AUTH_SCRIPT
    assert "card.className = 'modal-card'" in AUTH_SCRIPT
    assert "ok.className = 'btn-primary modal-btn-block'" in AUTH_SCRIPT
    assert "close.className = 'btn-ghost modal-btn-block'" in AUTH_SCRIPT


def test_redemption_only_uses_ruled_name_and_primary_confirm():
    """Sweep find during the #142a build: this page still carried the
    retired 'Analysis Report' name on its two action labels."""
    assert ">Generate Investigation Report</button>" in REDEMPTION
    assert ">View Investigation Report</a>" in REDEMPTION
    assert "Generate Analysis Report" not in REDEMPTION
    assert "View Analysis Report" not in REDEMPTION
    assert 'class="btn-small btn-primary" id="analysis-confirm"' in REDEMPTION


# --- 2. My Reports: card opens, Open control gone ---------------------------


def test_reports_rows_have_no_open_control_and_name_is_the_link():
    assert 'class="btn btn-ghost">Open</a>' not in REPORTS
    assert 'class="s3-name-link" href="/reports/{{ report.id }}"' in REPORTS


def test_reports_card_click_handler_is_interactive_safe():
    """The delegated handler must never navigate when the click lands
    on an interactive element inside the card row (the share-state
    Turn off button lives in the state cell)."""
    assert "e.target.closest('a, button, input, select, textarea, label')" in REPORTS
    assert "row.querySelector('.s3-name-link')" in REPORTS
    assert ".s3-table tbody tr.card{cursor:pointer}" in REPORTS


# --- 3. Titles ----------------------------------------------------------------


def test_report_title_no_longer_breaks_mid_word():
    head = CSS[CSS.index(".report-head h2"):]
    head = head[:head.index("}")]
    assert "break-all" not in head
    assert "overflow-wrap: anywhere" in head
    assert "color: var(--text)" in head


def test_reports_name_wraps_at_mobile_widths():
    """At <=640px the filename wraps (no nowrap/ellipsis truncation);
    the desktop single-line treatment is untouched."""
    mobile = REPORTS[REPORTS.index(".s3-report-main .name{"):]
    mobile = mobile[:mobile.index("}")]
    assert "white-space:normal" in mobile
    assert "overflow-wrap:anywhere" in mobile
    # The compact mobile action row ships with the same media block.
    assert ".s3-actions-row .btn{height:32px" in REPORTS
