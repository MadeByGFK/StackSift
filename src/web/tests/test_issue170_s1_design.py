"""Issue #170 S1: Report-surface design-alignment port.

Spec v1 (Decisions 2, 3, 6, 7, 9, 13, 14, 15) as amended by spec v2
amendments A1-A8. Teeth discipline: assertions on the NEW structure
(numbered section heads, evidence grid, premium card, stats notes,
numbered PDF headings + PDF evidence groups) FAIL on the base tree
(96511a4e); assertions pinning pre-existing honest copy verbatim are
regression gates and are labelled as such — they pass on both trees
(A8: a gate is not teeth).
"""

import json
import re

import pytest

from app import deep_dive as dd
from app.main import templates
from app.pdf_export import generate_deep_dive_pdf, generate_report_pdf
from app.vendor.diagnostics import (
    build_supporting_evidence, rank_candidates)
from app.vendor.insights import determine_health
from test_issue160_designed_reports import _norm, extract_pdf_text
from test_issue162_brief import _sample_artifact

NONE_MSG = (
    "No active incident established from the available log evidence. "
    "No escalation was detected in this log. This does not guarantee "
    "the system is healthy \u2014 persistent issues may not produce "
    "spikes.")
CORRELATED_CAPTION = (
    "Aligned with the degradation window, or persistent across "
    "the observation window; no shared cause is established.")
OBSERVED_CAPTION = "Shares infrastructure with the lead issue."
HYPOTHESIZED_CAPTION = (
    "Shares infrastructure with the lead issue and shows a possible "
    "contributor signal \u2014 unproven.")
PRIVACY_LINE = (
    "Uploads may be spooled to disk before redaction. Temporary files "
    "are cleaned up during normal processing. Redaction may miss "
    "sensitive data; review this report before sharing.")


def _se(observed=(), correlated=(), hypothesized=(),
        observed_total=None, correlated_total=None,
        hypothesized_total=None):
    return {
        "observed": list(observed), "correlated": list(correlated),
        "hypothesized": list(hypothesized),
        "observed_total": len(observed) if observed_total is None
        else observed_total,
        "correlated_total": len(correlated) if correlated_total is None
        else correlated_total,
        "hypothesized_total": len(hypothesized)
        if hypothesized_total is None else hypothesized_total,
    }


def _incident(se=None, **kw):
    base = {
        "type": "active_incident", "headline": "Active incident",
        "investigate_first": "db timeout", "starting_point": "Unknown",
        "timing_note": None, "other_candidates": [],
        "supporting_evidence": _se() if se is None else se,
    }
    base.update(kw)
    return base


def _bucket(label, warn=0, error=0, critical=0, total=None):
    return {"label": label, "warn": warn, "error": error,
            "critical": critical,
            "total": (warn + error + critical) if total is None
            else total}


def _ctx(**overrides):
    ctx = {
        "filename": "x.log", "elapsed": 0.5,
        "detected_format": "text", "adapted": False,
        "health": {"label": "No Significant Issues Detected",
                   "color": "green"},
        "results": {"total_lines": 200, "parsed_lines": 190,
                    "malformed_lines": 10,
                    "level_counts": {"ERROR": 5},
                    "service_counts": {}},
        "sorted_issues": [
            ["db timeout", {"level": "ERROR", "count": 7,
                            "services": ["db"]}],
            ["cache miss", {"level": "WARN", "count": 3,
                            "services": ["api"]}],
        ],
        "top_issue": ("cache miss", {"level": "WARN", "count": 3}),
        "diagnostic_issue": None, "diagnostic_explanation": None,
        "incident_section": {"type": "none", "headline": None,
                             "message": NONE_MSG},
        "notable_events": [], "timeline": [],
        "first_seen": None, "last_seen": None,
        "complexity_truncated": False, "complexity_notice": None,
        "current_user": None, "csrf_token": "t", "report_id": None,
    }
    ctx.update(overrides)
    return ctx


def _render(**overrides):
    return templates.env.get_template("report.html").render(
        **_ctx(**overrides))


def _owned(**overrides):
    base = {
        "current_user": object(), "report_id": "r1",
        "export_unlocked": False, "share_formats": [],
        "share_create_key": "a", "share_rotate_key": "b",
        "share_revoke_key": "c", "analysis_eligible": True,
        "analysis_reason": None, "analysis_result_id": None,
        "incident_section": _incident(),
    }
    base.update(overrides)
    return _render(**base)


def _group_segment(html, group):
    start = html.index(f'data-s1-group="{group}"')
    nxt = html.find('data-s1-group="', start + 10)
    return html[start:] if nxt == -1 else html[start:nxt]


# --- Section inventory ---------------------------------------------------


def test_s1_section_inventory_in_remake_order():
    html = _render(
        incident_section=_incident(se=_se(
            observed=[("shared symptom", 2, "ERROR")],
            correlated=[("timed peer", 4, "WARN")],
            hypothesized=[("possible contributor", 1, "ERROR")])),
        notable_events=[{"template": "rare critical", "level": "CRITICAL",
                         "count": 1}],
        timeline=[_bucket("10:00", warn=1), _bucket("10:05", error=2)],
    )
    positions = [html.index(f">{n}<") for n in
                 ("01", "02", "03", "04", "05")]
    assert positions == sorted(positions), positions
    for group in ("observed", "correlated", "hypothesized"):
        assert f'data-s1-group="{group}"' in html
    assert "Notable events" in html and "All issues" in html
    assert "Analysis notices" in html


def test_s1_deep_dive_numbered_brief_and_groups():
    projection = dd.public_projection(_sample_artifact())
    html = templates.env.get_template("deep_dive_report.html").render(
        analysis_projection=projection, filename="sample.log",
        is_sample=False, current_user=None, report_id=None,
        csrf_token="t")
    assert 'class="s1-section-head"' in html
    assert "Investigation Brief" in html
    assert "data-s1-group-index=" in html
    assert "data-s1-premium-card" not in html


# --- Incident 'none' (A3) -------------------------------------------------


def test_s1_incident_none_verbatim_no_grid():
    for incident in (
            {"type": "none", "headline": None, "message": NONE_MSG},
            {"type": "none", "headline": None, "message": NONE_MSG,
             "supporting_evidence": None},
    ):
        html = _render(incident_section=incident)
        assert NONE_MSG in html
        assert "s1-evidence-grid" not in html
        assert 'data-s1-group="correlated"' not in html


# --- Correlated sourcing (A1) --------------------------------------------


def _persistence_projection():
    """Persistence-only correlated membership through the REAL vendor
    pipeline: the correlated candidate shares NO infrastructure with
    the leader and there is NO degradation window — its temporal
    score comes from persistence across >=5 telemetry buckets (A1).
    """
    def mk(count, pool):
        return {
            "level": "ERROR", "count": count, "services": ["db"],
            "correlation": {"pool": [pool]}, "telemetry": {},
            "telemetry_buckets": {
                f"2026-10-11T12:{m:02d}": {
                    "active": {"min": 1, "max": 2, "count": 3}}
                for m in range(0, 60, 5)},
            "correlation_samples": [],
            "first_seen": "2026-10-11T12:00:00.000Z",
            "last_seen": "2026-10-11T12:55:00.000Z",
        }
    issues = {
        "leader pool exhausted": mk(100, "p1"),
        "persistent unrelated timeout": mk(40, "p9"),
        "shared infra symptom": mk(10, "p1"),
    }
    _out = rank_candidates(issues, [])
    ranked, window = _out[0], _out[1]
    assert window is None  # no degradation window: persistence only
    se = build_supporting_evidence(
        "leader pool exhausted", issues["leader pool exhausted"],
        ranked, issues, window)
    assert [i[0] for i in se["correlated"]] == [
        "persistent unrelated timeout"]
    assert [i[0] for i in se["observed"]] == ["shared infra symptom"]
    return se


def test_s1_correlated_items_equal_projection_and_caption():
    se = _persistence_projection()
    html = _render(incident_section=_incident(se=se))
    segment = _group_segment(html, "correlated")
    for item in se["correlated"]:
        assert item[0] in segment
    assert "shared infra symptom" not in segment
    assert CORRELATED_CAPTION in segment
    # PR #171 Codex P2-1: correlated membership never compares the
    # candidate's buckets with the lead issue's — the caption must
    # not claim a shared time pattern with the lead issue.
    assert "same time pattern as the lead issue" not in html
    assert OBSERVED_CAPTION in _group_segment(html, "observed")
    assert HYPOTHESIZED_CAPTION in _group_segment(html, "hypothesized")
    # A1: the withdrawn caption must never render (regression gate).
    assert "shared failure chain" not in html


def test_s1_not_shown_count_is_total_minus_displayed():
    se = _se(correlated=[("a", 1, "WARN"), ("b", 2, "ERROR")],
             correlated_total=5)
    html = _render(incident_section=_incident(se=se))
    assert "3 more not shown" in _group_segment(html, "correlated")


def test_s1_single_issue_no_fabricated_correlations():
    html = _render(incident_section=_incident(se=_se()))
    segment = _group_segment(html, "correlated")
    assert "s1-evidence-item" not in segment
    assert CORRELATED_CAPTION in segment


# --- Timeline gate + stacked heights --------------------------------------


def test_s1_timeline_gate_below_two_buckets():
    for timeline in ([], [_bucket("10:00", warn=3)]):
        html = _render(timeline=timeline)
        assert "Incident timeline" not in html
        assert "data-s1-peak" not in html
        assert 'class="timeline"' not in html


def test_s1_timeline_heights_from_severity_counters_not_total():
    # bucket.total counts ALL timestamped events (incl. INFO); the
    # stacked height must use warn+error+critical only (A-audit).
    html = _render(timeline=[
        _bucket("10:00", warn=1, error=1, critical=1, total=99),
        _bucket("10:05", warn=1, total=50),
    ])
    assert "Peak: 3 warnings + errors at 10:00" in html
    assert "height: 100.0%" in html     # 3/3 severity stack
    assert "height: 33.33333333333333%" in html  # 1/3 severity stack


# --- Health pill: all seven labels ----------------------------------------


@pytest.mark.parametrize("kwargs,label,color", [
    (dict(level_counts={"CRITICAL": 1}), "Critical", "red"),
    (dict(level_counts={}, bucket_totals=[10, 10, 30, 30, 10]),
     "Elevated Incident Activity", "red"),
    (dict(level_counts={}, bucket_totals=[10, 10, 20, 20, 10]),
     "Increased Error Activity", "yellow"),
    (dict(level_counts={}, bucket_totals=[12, 12, 12, 12]),
     "No Escalation Detected", "green"),
    (dict(level_counts={}, bucket_totals=[0, 0, 0]),
     "No Significant Issues Detected", "green"),
    (dict(level_counts={}), "Health Undetermined", "gray"),
    (dict(level_counts={}, events_total=5, timestamped_total=0),
     "Timestamps Not Recognized", "gray"),
])
def test_s1_health_labels_render_verbatim(kwargs, label, color):
    got_label, got_color = determine_health(**kwargs)
    assert (got_label, got_color) == (label, color)  # fixture sanity
    html = _render(health={"label": got_label, "color": got_color})
    assert f'data-health-label="{label}"' in html
    assert f'data-health-color="{color}"' in html
    assert f'>{label}</span>' in html
    assert "Action required" not in html  # remake suffix has no source
    assert "Healthy" not in html.replace("healthy", "")


# --- Copy pins (Decision 9 / A6) -------------------------------------------


def test_s1_copy_pins_verbatim():
    """Regression gates (pass on base) for the strings that do NOT
    move textually, plus teeth on the new §05 structure."""
    html = _render()
    assert PRIVACY_LINE in html
    assert "never shown in this report" not in html
    assert 'data-s1-group=' not in html  # 'none' case: no grid (A3)
    singular = _render(results={"total_lines": 10, "parsed_lines": 9,
                                "malformed_lines": 1,
                                "level_counts": {}, "service_counts": {}})
    assert "line couldn't be parsed and was excluded." in singular
    plural = _render()
    assert "lines couldn't be parsed and were excluded." in plural
    adapted = _render(adapted=True)
    assert "Your file was detected as" in adapted
    assert "converted automatically." in adapted
    capped = _render(complexity_truncated=True,
                     complexity_notice="Analysis covered the 3 most "
                                       "frequent of 9 issue patterns.")
    assert "\u26a0\ufe0f Analysis limited:" in capped
    assert "most frequent of 9 issue patterns." in capped
    # Teeth: the notices live under the numbered §05 head on the
    # built tree only.
    assert ">05<" in html and "Analysis notices" in html


# --- Stats notes (Decision 13) ----------------------------------------------


def test_s1_stats_notes_computed_and_no_file_size():
    html = _render()
    assert "95.00% of total" in html
    assert "5.00% could not be parsed" in html
    assert "10 total occurrences" in html  # 7 + 3 issue counts
    assert not re.search(r"\d+(\.\d+)?\s?(MB|KB|GB)\b", html)
    empty = _render(
        results={"total_lines": 0, "parsed_lines": 0,
                 "malformed_lines": 0, "level_counts": {},
                 "service_counts": {}},
        sorted_issues=[])
    assert "% of total" not in empty
    assert "total occurrences" not in empty


# --- Premium card gating (Decision 6 as amended by A5) ----------------------


def test_s1_premium_card_only_for_owned_eligible_standard():
    html = _owned()
    assert "data-s1-premium-card" in html
    # PREMISE CHANGED (#164 Phase A): the card carries the ruled
    # dollar copy (the #170 brief's "no dollar copy pre-#164A"
    # interim premise is superseded by the Phase A build itself).
    assert "Investigation Report costs $9" in html
    assert "Analysis Report costs 3 credits." not in html
    assert 'id="premium-upsell-btn"' in html
    assert "50 MB" not in html
    # Already purchased -> the card never re-offers.
    assert "data-s1-premium-card" not in _owned(
        analysis_result_id="derived-1")
    # PR #171 Codex P2-2 / A5: an older-generator prior purchase
    # (analysis_prior_exists, result id cleared by report_view for
    # the disclosed modal upgrade path) is still an already-purchased
    # report — the card must not render; the upgrade stays available
    # through the Actions modal, which carries the disclosure copy.
    assert "data-s1-premium-card" not in _owned(
        analysis_prior_exists=True)
    # Not eligible (e.g. legacy/insufficient evidence) -> no card.
    assert "data-s1-premium-card" not in _owned(analysis_eligible=False)
    # Anonymous immediate render -> no card.
    assert "data-s1-premium-card" not in _render(
        incident_section=_incident())
    # Demo render -> no card even with an owned-looking context.
    assert "data-s1-premium-card" not in _owned(is_demo=True)


def test_s1_free_paid_line_both_directions():
    from app.service import analyze_upload
    from app.sample_data import SAMPLE_FILENAME, SAMPLE_LOG
    payload = analyze_upload(SAMPLE_FILENAME, SAMPLE_LOG.encode(),
                             use_alarm=False)
    brief = dd.build_deep_dive(payload)["brief"]
    lead_sentence = next(s for s in brief["summary"]
                         if "investigation lead" in s)
    free_html = _owned()  # owned free report: card present...
    assert "data-s1-premium-card" in free_html
    assert lead_sentence not in free_html  # ...but no Brief content
    assert dd.BRIEF_NOT_ESTABLISHED not in free_html
    paid_html = templates.env.get_template(
        "deep_dive_report.html").render(
            analysis_projection=dd.public_projection(
                dd.build_deep_dive(payload)),
            filename=SAMPLE_FILENAME, is_sample=False,
            current_user=None, report_id=None, csrf_token="t")
    assert dd.BRIEF_NOT_ESTABLISHED in paid_html
    assert "data-s1-premium-card" not in paid_html


# --- Sample invariants (Decision 15) -----------------------------------------


def test_s1_sample_invariants_survive_reskin():
    projection = dd.public_projection(_sample_artifact())
    html = templates.env.get_template("deep_dive_report.html").render(
        analysis_projection=projection, filename="sample.log",
        is_sample=True,
        branding={"business_name": "WellInstance",
                  "client_name": None, "report_title": None,
                  "accent": None, "logo_url": None})
    assert "SAMPLE \u2014 generated by StackSift" in html
    assert "WellInstance" in html
    assert "<form" not in html.lower()
    assert "data-s1-premium-card" not in html
    assert "Investigation Brief" in html


# --- Standard PDF gap-close (Decision 14 as amended by A3) -------------------


def _pdf_manifest(**overrides):
    manifest = {
        "filename": "x.log",
        "results": {"total_lines": 200, "parsed_lines": 190,
                    "malformed_lines": 10},
        "health": {"label": "Critical", "color": "red"},
        "sorted_issues": [["db timeout", {"level": "ERROR",
                                          "count": 7}]],
        "incident_section": _incident(se=_se(
            observed=[("shared symptom", 2, "ERROR")],
            correlated=[("timed peer", 4, "WARN")],
            hypothesized=[("possible contributor", 1, "ERROR")])),
        "notable_events": [{"template": "rare critical",
                            "level": "CRITICAL", "count": 1}],
        "timeline": [_bucket("10:00", warn=1), _bucket("10:05", error=2)],
        "adapted": True,
    }
    manifest.update(overrides)
    return json.dumps(manifest, default=str)


def test_s1_standard_pdf_numbered_sections_and_evidence_groups():
    text = _norm(extract_pdf_text(generate_report_pdf(
        _pdf_manifest(), "x.log")))
    positions = [text.index(h) for h in (
        "01 Incident", "02 Notable Events", "03 Timeline",
        "04 All Issues", "05 Analysis Notices")]
    assert positions == sorted(positions), positions
    # Newly displayed (A3): the evidence groups exist in the PDF.
    assert "shared symptom" in text and "timed peer" in text
    assert "possible contributor" in text
    assert "no shared cause is established" in text
    assert "converted automatically" in text


def test_s1_standard_pdf_incident_none_no_groups():
    text = _norm(extract_pdf_text(generate_report_pdf(
        _pdf_manifest(incident_section={
            "type": "none", "headline": None, "message": NONE_MSG}),
        "x.log")))
    assert "No active incident established" in text
    assert "does not guarantee" in text
    assert "timed peer" not in text


def test_s1_deep_dive_pdf_gains_no_standard_sections():
    """A3: no standard timeline/incident is added to deep-dive PDF."""
    blob = generate_deep_dive_pdf(
        json.dumps(_sample_artifact()), "sample.log")
    text = _norm(extract_pdf_text(blob))
    assert "01 Incident" not in text
    assert "03 Timeline" not in text


# --- Compare / batch shared styling only --------------------------------------


def test_s1_compare_batch_shared_heading_styling():
    compare = templates.env.get_template("compare_report.html").render(
        filename="a \u2192 b", no_material_differences=False,
        resolved_note="note", current_user=None, report_id=None,
        csrf_token="t",
        summary={"new": 0, "resolved": 0, "volume_changed": 0,
                 "severity_shifted": 0},
        material_change={"version": 1, "min_absolute": 5,
                         "min_fraction_of_a": 0.5},
        new=[], resolved=[], volume_changes=[], severity_shifts=[],
        shared=[])
    assert 'class="s1-section-head"' in compare
    assert "No material differences were found" not in compare
    batch = templates.env.get_template("batch_report.html").render(
        filename="batch", summary_sentence="Two files.",
        summary={"file_count": 0, "total_lines": 0, "parsed_lines": 0,
                 "malformed_lines": 0, "unique_issue_patterns": 0,
                 "first_seen": None, "last_seen": None},
        combined_issues=[], files=[], current_user=None,
        report_id=None, csrf_token="t")
    assert 'class="s1-section-head"' in batch
    assert PRIVACY_LINE in batch  # regression gate: string unmoved
