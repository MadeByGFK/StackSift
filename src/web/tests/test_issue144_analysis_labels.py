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
_TS = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}"


def _cards(page_text):
    """Map report id -> that row's <tr class="card s3-row"> markup only.

    Keyed by the row's own View link (a source row's Analysis link
    also points at the derived report, so the View link is the
    unambiguous row identity, mirroring test_deep_dive_paid).
    Each chunk is truncated at </tr> so page-level markup after the
    list (modals etc.) cannot leak into a row's assertions.
    """
    cards = {}
    for chunk in page_text.split('<tr class="card s3-row">')[1:]:
        card = chunk.split("</tr>")[0]
        m = re.search(r'href="/reports/([0-9a-f-]{36})" class="btn btn-ghost">View', card)
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


def test_deep_dive_row_timestamp_reads_created_not_analyzed(auth_env):
    rows, _ = _mixed_list(auth_env)
    card = rows["deep_dive"]
    assert re.search(rf"Created {_TS}", card)
    assert "Analyzed" not in card


def test_source_rows_keep_analyzed_and_have_no_title(auth_env):
    rows, _ = _mixed_list(auth_env)
    for kind in ("analysis", "comparison", "batch"):
        card = rows[kind]
        assert re.search(rf"Analyzed {_TS}", card), kind
        assert "Created" not in card, kind
        assert _TITLE not in card, kind


def test_mixed_list_renders_both_row_kinds(auth_env):
    rows, page_text = _mixed_list(auth_env)
    # Exactly one titled row on the whole page: the deep_dive row.
    assert page_text.count(_TITLE) == 1
    assert _TITLE in rows["deep_dive"]
    assert re.search(r"Created ", rows["deep_dive"])
    for kind in ("analysis", "comparison", "batch"):
        assert re.search(r"Analyzed ", rows[kind]), kind
