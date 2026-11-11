"""Issue #144: My Reports row labels for Analysis Reports.

Founder direction (2026-11-04, PLANNED backlog): in My Reports an
Analysis Report (deep_dive) row was indistinguishable from a source
report row. Two labeling fixes ONLY — no behavior, pricing, or
button changes (Extend/Share for Analysis Reports are the separate
parked item #145 and are NOT touched here):

1. Title: deep_dive rows carry a title above the report filename
   that reads exactly "Investigation Report".
   (Name updated 2026-11-10 under the founder naming sweep in
   #170 S3: the paid deliverable is "Investigation Report";
   "Analysis Report" is retired as a user-facing name.)
2. Timestamp label: deep_dive rows read "Created <timestamp>";
   analysis / comparison / batch rows keep "Analyzed <timestamp>".
   PREMISE CHANGED (founder fidelity ruling 2026-11-10, PR #177
   S3-G4): the Analyzed/Created prefix is SUPERSEDED — every
   row's Date cell is now two lines, "Mon DD, YYYY" over
   "HH:MM UTC", with no prefix for any kind; deep_dive rows stay
   distinguished by the title in (1). The timestamp tests below
   pin the new two-line format at the same strength (per-kind
   assertions over the same mixed list).

Surface: My Reports (manage reports) — one-job-per-page rule.

TEETH: every test in this file FAILS on the pristine base tree
(staging 1a8af7ca: no title element, every row reads "Analyzed")
and PASSES on the built tree. No pre-existing test's premise is
changed; this file is new.
"""

import re

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import _custom_result, _setup

_TITLE = '<div class="kind-title">Investigation Report</div>'
_DATE_LINE = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{2}, \d{4}"
_TIME_LINE = r"\d{2}:\d{2} UTC"


def _cards(page_text):
    """Map report id -> that report's row markup (main row + the
    row-under actions row).

    Keyed by the row's own Open link (a source row's Investigation
    Report link also points at the derived report, so the Open
    link is the unambiguous row identity, mirroring
    test_deep_dive_paid). (Label premise changed 2026-11-10,
    S3-G1: "View" is now "Open".)
    PREMISE CHANGED (founder ruling 2026-11-10 21:57, S3 row-under
    fold-in on PR #179): the Open link now lives in the actions
    row UNDER the main row, so a chunk can no longer be truncated
    at the first </tr> — the old truncation cut every chunk before
    its Open link and all four tests failed on the keying
    assertion. Instead the table is isolated first (so page-level
    markup after the list — modals etc. — cannot leak into a
    row's assertions, the protection the truncation provided) and
    each chunk spans both <tr>s up to the next report's main row;
    every assertion in this file is unchanged and at the same
    strength.
    """
    table = page_text.split('<table class="s3-table">')[1]
    table = table.split("</table>")[0]
    cards = {}
    for chunk in table.split('<tr class="card s3-row">')[1:]:
        card = chunk
        m = re.search(r'href="/reports/([0-9a-f-]{36})" class="btn btn-ghost">Open', card)
        assert m, card[:200]
        cards[m.group(1)] = card
    return cards


def _mixed_list(auth_env):
    """One logged-in user with one row of each kind; returns cards."""
    _, user_id, rid, _csrf = _setup(auth_env)
    deep_dive_id = _custom_result(
        auth_env, user_id,
        {"filename": "deep-source.log", "report_kind": "deep_dive"},
        report_type="deep_dive")
    comparison_id = _custom_result(
        auth_env, user_id, {"filename": "compare.log"},
        report_type="comparison")
    batch_id = _custom_result(
        auth_env, user_id,
        {"filename": "batch.log", "report_kind": "batch"},
        report_type="analysis")
    page = auth_env.client.get("/reports")
    assert page.status_code == 200
    cards = _cards(page.text)
    return {
        "analysis": cards[str(rid)],
        "deep_dive": cards[str(deep_dive_id)],
        "comparison": cards[str(comparison_id)],
        "batch": cards[str(batch_id)],
    }, page.text


def test_deep_dive_row_shows_analysis_report_title_above_filename(auth_env):
    rows, _ = _mixed_list(auth_env)
    card = rows["deep_dive"]
    assert _TITLE in card
    # The title sits ABOVE the filename in the row.
    assert card.index(_TITLE) < card.index("deep-source.log")


def test_deep_dive_row_date_cell_is_two_line_without_prefix(auth_env):
    # PREMISE CHANGED (S3-G4 supersession, 2026-11-10): no
    # Created/Analyzed prefix remains — the date cell is the
    # two-line date over time-UTC for every kind.
    rows, _ = _mixed_list(auth_env)
    card = rows["deep_dive"]
    assert 'class="s3-date-line"' in card and re.search(_DATE_LINE, card)
    assert 'class="s3-date-sub"' in card and re.search(_TIME_LINE, card)
    assert "Created" not in card
    assert "Analyzed" not in card


def test_source_rows_two_line_date_and_no_title(auth_env):
    # PREMISE CHANGED (S3-G4 supersession, 2026-11-10): source
    # rows carry the same two-line date cell and no prefix; the
    # no-title gate is unchanged.
    rows, _ = _mixed_list(auth_env)
    for kind in ("analysis", "comparison", "batch"):
        card = rows[kind]
        assert 'class="s3-date-line"' in card and re.search(_DATE_LINE, card), kind
        assert 'class="s3-date-sub"' in card and re.search(_TIME_LINE, card), kind
        assert "Analyzed" not in card, kind
        assert "Created" not in card, kind
        assert _TITLE not in card, kind


def test_mixed_list_renders_both_row_kinds(auth_env):
    rows, page_text = _mixed_list(auth_env)
    # Exactly one titled row on the whole page: the deep_dive row.
    assert page_text.count(_TITLE) == 1
    assert _TITLE in rows["deep_dive"]
    for kind in ("deep_dive", "analysis", "comparison", "batch"):
        assert 'class="s3-date-line"' in rows[kind] and re.search(_DATE_LINE, rows[kind]), kind
        assert 'class="s3-date-sub"' in rows[kind] and re.search(_TIME_LINE, rows[kind]), kind
