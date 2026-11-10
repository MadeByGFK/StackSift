"""Issue #170 fidelity slice: S1 G1-G14, S2 G1, S4 G1-G2, renames,
and the adopted CALL projections (S1-C1 timestamp, S1-C2 SS-ID,
S1-C3 redacted excerpts, S1-C4 templated caption, S1-C5 callout
source/first-seen, S3-C1 My Reports subline).

TEETH: every test here asserts the NEW structure/projection and
FAILS on the pre-build tree (94c271dd) — verified by running this
file against that tree. The G1 control-structure tests are the
anchor: old Actions-menu selectors gone, direct controls carrying
the same form actions / endpoints / data-confirm gating.
"""

import re
from datetime import datetime, timezone
from types import SimpleNamespace

from app.main import templates


# --- Pure CALL-projection helpers ------------------------------------------


def test_ss_id_format_and_daily_sequence_shape():
    from app import fidelity
    when = datetime(2026, 11, 10, 14, 32, tzinfo=timezone.utc)
    assert fidelity.format_ss_id(when, 1) == "SS-20261110-0001"
    assert fidelity.format_ss_id(when, 42) == "SS-20261110-0042"


def test_ss_id_legacy_derivation_is_stable():
    from app import fidelity
    import uuid
    rid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    when = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
    a = fidelity.derive_ss_id(rid, when)
    assert a == fidelity.derive_ss_id(rid, when)
    assert re.fullmatch(r"SS-20261020-\d{4}", a)
    assert fidelity.derive_ss_id(None, when) is None
    assert fidelity.derive_ss_id(rid, None) is None


def test_honest_format_label_only_two_values():
    from app import fidelity
    # S1-C1 format half as ruled: NO fine taxonomy.
    assert fidelity.honest_format_label("jsonlines") == "JSON-lines"
    assert fidelity.honest_format_label("text") == "Plain-text"
    assert fidelity.honest_format_label("anything") == "Plain-text"


def test_timeline_caption_is_templated_from_buckets_only():
    from app import fidelity
    timeline = [
        {"label": "09:00", "warn": 1, "error": 0, "critical": 0},
        {"label": "09:05", "warn": 0, "error": 3, "critical": 1},
        {"label": "09:10", "warn": 0, "error": 0, "critical": 0},
    ]
    cap = fidelity.timeline_caption(timeline)
    assert cap == ("5 warnings + errors across the window "
                   "09:00–09:10 UTC; peak of 4 at 09:05.")
    assert fidelity.timeline_caption([]) is None
    assert fidelity.timeline_caption(timeline[:1]) is None
    quiet = [dict(b, warn=0, error=0, critical=0) for b in timeline]
    assert fidelity.timeline_caption(quiet) is None


def test_observed_excerpts_pass_redaction_and_fail_closed():
    from app import fidelity
    results = {"diagnostic_evidence": {"groups": {
        "db timeout": {"excerpts": [
            {"text": "password=hunter2 db timeout",
             "analysis_line_number": 7}]}}}}
    out = fidelity.observed_excerpts(results, ["db timeout"])
    assert "hunter2" not in out["db timeout"][0]["text"]
    assert "db timeout" in out["db timeout"][0]["text"]
    assert out["db timeout"][0]["analysis_line_number"] == 7
    # No evidence / no templates -> no excerpts (never fabricated).
    assert fidelity.observed_excerpts({}, ["db timeout"]) == {}
    assert fidelity.observed_excerpts(results, []) == {}
    assert fidelity.observed_excerpts(results, ["absent"]) == {}


def test_assign_ss_id_daily_sequence():
    # Stored generation: sequence increments within the day, resets
    # the next day, and the value persists on the row.
    import uuid as _uuid
    from datetime import timedelta
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import credits, models
    from app.db import Base
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    user = models.User(email="ss@example.com", email_verified=True)
    db.add(user)
    db.flush()
    when = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)

    def _row():
        r = models.Result(
            user_id=user.id, free_request_id=_uuid.uuid4().hex,
            type="analysis", storage_manifest="{}",
            integrity_digest="x" * 64, byte_count=2,
            ready_at=when, expires_at=when + timedelta(days=7))
        db.add(r)
        db.flush()
        return r

    r1, r2 = _row(), _row()
    assert credits.assign_ss_id(db, r1, when) == "SS-20261110-0001"
    assert credits.assign_ss_id(db, r2, when) == "SS-20261110-0002"
    db.flush()
    assert r1.ss_id == "SS-20261110-0001"  # stable once assigned
    nxt = when + timedelta(days=1)
    r3 = _row()
    assert credits.assign_ss_id(db, r3, nxt) == "SS-20261111-0001"
    db.close()


# --- Template composition (report.html) -------------------------------------

NONE_MSG = (
    "No active incident established from the available log evidence. "
    "No escalation was detected in this log. This does not guarantee "
    "the system is healthy — persistent issues may not produce "
    "spikes.")


def _ctx(**overrides):
    ctx = {
        "filename": "x.log", "elapsed": 0.5,
        "detected_format": "text", "adapted": False,
        "health": {"label": "Critical", "color": "red"},
        "results": {"total_lines": 200, "parsed_lines": 190,
                    "malformed_lines": 10,
                    "level_counts": {"ERROR": 5},
                    "service_counts": {"db": 4}},
        "sorted_issues": [
            ["db timeout", {"level": "ERROR", "count": 7,
                            "services": ["db"]}],
            ["cache miss", {"level": "WARN", "count": 3,
                            "services": ["api"]}],
        ],
        "top_issue": ("cache miss", {"level": "WARN", "count": 3,
                                     "services": ["api"],
                                     "first_seen": "09:01:00"}),
        "diagnostic_issue": ("db timeout",
                             {"level": "ERROR", "count": 7,
                              "services": ["HikariPool-1"],
                              "first_seen": "09:20:14"}),
        "diagnostic_explanation": ["telemetry shows 1/2 pressure signals"],
        "incident_section": {"type": "none", "headline": None,
                             "message": NONE_MSG},
        "notable_events": [{"template": "rare critical",
                            "level": "CRITICAL", "count": 2,
                            "source": "api"}],
        "timeline": [
            {"label": "09:00", "warn": 1, "error": 0, "critical": 0,
             "total": 1},
            {"label": "09:05", "warn": 0, "error": 2, "critical": 0,
             "total": 2},
        ],
        "timeline_caption": ("3 warnings + errors across the window "
                             "09:00–09:05 UTC; peak of 2 at 09:05."),
        "first_seen": "09:00:00", "last_seen": "09:59:00",
        "complexity_truncated": False, "complexity_notice": None,
        "current_user": None, "csrf_token": "t", "report_id": None,
        "ss_id": "SS-20261110-0007",
        "analysis_timestamp": "Nov 10, 2026 · 14:32 UTC",
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
    }
    base.update(overrides)
    return _render(**base)


def test_g1_direct_controls_replace_actions_menu():
    html = _owned()
    assert 'id="actions-btn"' not in html
    assert 'id="actions-menu"' not in html
    assert "btn-small\" id=\"actions" not in html
    assert 'data-s1-actions' in html
    cluster = html[html.index('data-s1-actions'):
                   html.index('id="analysis-modal"')]
    # Same endpoints + gating as the retired menu.
    assert 'action="/reports/r1/pdf"' in cluster
    assert 'action="/reports/r1/exports/csv"' in cluster
    assert 'action="/reports/r1/exports/json"' in cluster
    assert cluster.count("data-confirm") == 3
    assert 'class="s1-btn-gold" data-export="pdf"' in cluster
    assert 'id="analysis-btn"' in cluster
    assert 'id="share-btn"' in cluster
    # Unlocked state flips the tags to Free.
    unlocked = _owned(export_unlocked=True)
    ucluster = unlocked[unlocked.index('data-s1-actions'):
                        unlocked.index('id="analysis-modal"')]
    assert ">Free</span>" in ucluster
    assert "export-unlocked" in ucluster


def test_g2_breadcrumb_and_c2_eyebrow_and_c1_head_meta():
    html = _render()
    assert 'class="s1-breadcrumb"' in html
    assert "← My Reports" in html and "Report detail" in html
    assert 'data-ss-id' in html and "SS-20261110-0007" in html
    assert "Analyzed Nov 10, 2026 · 14:32 UTC" in html
    # Honest format label only — no fine taxonomy anywhere.
    assert "Plain-text log format" in html
    assert "Logback" not in html


def test_g3_premium_card_composition_and_rename():
    html = _owned()
    assert "Get the Investigation Report — $9" in html
    assert "A client-ready brief with the investigation lead" in html
    assert 'id="premium-upsell-btn"' in html
    assert "Get the Analysis Report" not in html
    # #164 terms CONTENT verbatim (composition only).
    assert "Investigation Report costs $9, paid by card at checkout." in html
    assert "disputes@goodfolkdigital.com" in html


def test_g4_callout_composition_and_c5_footer():
    html = _render()
    assert 'data-s1-callout' in html
    assert 'data-callout-source' in html and "HikariPool-1" in html
    assert 'data-callout-first-seen' in html
    assert "First seen 09:20:14" in html
    assert "7 occurrences" in html


def test_g5_g6_g7_g8_g9_g10_composition():
    incident = {
        "type": "active_incident", "headline": "Active incident",
        "investigate_first": "db timeout",
        "starting_point": "node-1 · HikariPool-1",
        "timing_note": None, "other_candidates": [],
        "supporting_evidence": {
            "observed": [("shared symptom", 2, "ERROR")],
            "correlated": [], "hypothesized": [],
            "observed_total": 1, "correlated_total": 0,
            "hypothesized_total": 0},
    }
    html = _render(
        incident_section=incident,
        observed_excerpts={"shared symptom": [
            {"text": "redacted excerpt line",
             "analysis_line_number": 3}]})
    # G5 two-field panel
    assert 'data-s1-incident-start' in html
    assert "Starting point" in html and "node-1 · HikariPool-1" in html
    # G6 markers + C3 excerpt block inside Observed
    assert 's1-marker-observed' in html
    assert 'data-s1-excerpt' in html and "redacted excerpt line" in html
    assert "analysis line 3" in html
    # G7 un-numbered sections gone
    assert "Severity breakdown" not in html
    assert "By service" not in html
    # G8 event rows with source subline + occurrences wording
    assert 'data-s1-event' in html and "rare critical" in html
    assert "2 occurrences" in html
    # G9 3-column table: no Source column, plain counts, footer label
    assert "<th>Source</th>" not in html
    assert "Total issue occurrences" in html
    # G10 asides
    assert "5-minute buckets · UTC" in html
    assert "2 patterns · 10 occurrences" in html
    # C4 caption rendered from context
    assert 'data-s1-timeline-caption' in html
    assert "peak of 2 at 09:05" in html


def test_g11_footer_band_and_g12_tagline_and_g13_window():
    html = _render()
    assert 'data-s1-footer-band' in html
    assert "INVESTIGATION REPORT" in html
    assert "SS-20261110-0007" in html
    # A5: no generated timestamp in the free template's band.
    band = html[html.index('data-s1-footer-band'):]
    band = band[:band.index("</div>")]
    assert "Generated" not in band
    assert "Your logs. Your insights. Your control." in html
    assert 'data-s1-window' in html
    assert "Log window 09:00:00 – 09:59:00" in html


def test_g14_notice_tags_and_coverage_inside_05():
    html = _render(complexity_truncated=True,
                   complexity_notice="Analysis covered the 3 most "
                                     "frequent of 9 issue patterns.")
    assert "Partial coverage" in html
    assert "95.00% parsed" in html
    assert "Redaction applied" in html
    # Coverage notice lives inside §05 (after the 05 head, not above stats)
    assert html.index("Analysis notices") < html.index("Partial coverage")
    assert html.index("Partial coverage") > html.index('class="stats"')


def test_renames_in_modal_copy():
    html = _owned(analysis_prior_exists=True)
    assert "A previous Investigation Report exists" in html
    assert "A previous Analysis Report exists" not in html
    assert "Generate Investigation Report" in html
    assert "View Investigation Report" in html


# --- Deep-dive template -------------------------------------------------------


def test_deep_dive_direct_controls_and_renames():
    from app import deep_dive as dd
    from test_issue162_brief import _sample_artifact
    projection = dd.public_projection(_sample_artifact())
    html = templates.env.get_template("deep_dive_report.html").render(
        analysis_projection=projection, filename="sample.log",
        is_sample=False, current_user=object(), report_id="r9",
        csrf_token="t", export_unlocked=True,
        branding=None, branding_values=None,
        ss_id="SS-20261110-0009")
    assert 'id="actions-btn"' not in html
    assert 'id="actions-menu"' not in html
    assert 'data-s1-actions' in html
    assert 'class="s1-breadcrumb"' in html
    assert "Investigation Report — sample.log" in html
    assert "Analysis Report —" not in html
    # §01 heading rename (template surface only)
    assert ('<h3 class="section-title" style="margin-top:0">'
            'Investigation Report</h3>') in html
    assert ('<h3 class="section-title" style="margin-top:0">'
            'Investigation Brief</h3>') not in html
    assert 'data-s1-footer-band' in html
    assert "SS-20261110-0009" in html


# --- S2 / S4 / S3 surfaces -----------------------------------------------------


def test_s2_hero_copy_and_tagline():
    html = templates.env.get_template("index.html").render(
        current_user=None, csrf_token="t", error=None, remaining=10)
    assert "<h1>Analyze a log file</h1>" in html
    assert ("Drop in a log file and get a severity-ranked incident "
            "summary — what failed first, what it affected, and what "
            "to check next.") in html
    assert "Your logs. Your insights. Your control." in html
    assert "Drop in a log file.<br>" not in html


def test_s4_page_head_and_field_rows_plan_deferred():
    user = SimpleNamespace(email="owner@example.com",
                           display_name=None, email_verified=True)
    html = templates.env.get_template("settings.html").render(
        user=user, current_user=user, sessions=[],
        current_session_id="s1", csrf_token="t",
        linked_providers=set(), balance_summary={"balance": 7},
        purchases=[], pack_names={}, share_links=[])
    assert 'data-s4-page-head' in html
    assert '<p class="s4-eyebrow">Settings</p>' in html
    assert "<h1>Settings</h1>" in html
    assert 'class="s4-field-label">Email<' in html
    assert 'class="s4-field-label">Plan<' in html
    # S4-C1 deferred: truthful interim text, NOT the dollar-model line.
    assert "Credit packs — 7 credits available" in html
    assert "Free analysis · pay per deliverable" not in html
    assert 'class="s4-field-label">Log out<' in html
    # S4-C2 deferred: no share-default toggle built.
    assert "Share links by default" not in html


def test_s3_subline_ss_id_and_format():
    row = SimpleNamespace(
        id="r1", filename="x.log", type="analysis", severity="ok",
        created_at=datetime(2026, 11, 10, 14, 32,
                            tzinfo=timezone.utc),
        expires_at=datetime(2026, 11, 17, 14, 32,
                            tzinfo=timezone.utc),
        days_left=7, report_kind=None, redemption_only=False,
        share_active=False, share_formats=[], export_unlocked=False,
        analysis_eligible=True, analysis_reason=None,
        analysis_result_id=None, entitlement_available=False,
        redemption_deadline=None, retention_key="k",
        share_create_key="a", share_rotate_key="b",
        share_revoke_key="c", ss_id="SS-20261110-0003",
        format_label="JSON-lines")
    html = templates.env.get_template("reports.html").render(
        reports=[row], current_user=object(), csrf_token="t",
        page=1, total_pages=1, total=1, product_ready=True,
        retention_extension_days=90, retention_extension_cost=1)
    assert 'data-s3-report-sub' in html
    assert "SS-20261110-0003 · JSON-lines" in html
