"""Phase C validation tests."""

def test_persistent_incident_without_escalation():
    """A flat-but-persistent incident must remain diagnosable.
    Escalation is a signal, not a requirement."""
    from stacksift.diagnostics import rank_candidates
    from stacksift.insights import build_timeline

    # Simulate: constant high error rate, no escalation spike
    # (timeline would be flat)
    issues = {
        "pool exhausted": {
            "level": "ERROR", "count": 100,
            "services": ["db"],
            "correlation": {"pool": ["p1"]},
            "telemetry": {"active": {"min": 40, "max": 40}},
            "telemetry_buckets": {
                f"2026-10-11T12:{m:02d}": {"active": {"min": 40, "max": 40, "count": 10}}
                for m in range(0, 60, 5)
            },
            "correlation_samples": [],
            "first_seen": "2026-10-11T12:00:00.000Z",
            "last_seen": "2026-10-11T12:55:00.000Z",
        }
    }
    # Empty timeline = no escalation detected
    ranked, window = rank_candidates(issues, [])
    assert window is None, "should handle missing escalation window"
    assert len(ranked) == 1
    # Should still produce a ranking (not crash, not empty)
    assert ranked[0][1] > 0


def test_misleading_infrastructure_warning():
    """Infrastructure warning should not auto-win without evidence."""
    from stacksift.diagnostics import rank_candidates

    issues = {
        # Infrastructure warning, isolated, no corroboration
        "db warning": {
            "level": "WARN", "count": 1,
            "services": ["database-service"],
            "correlation": {},
            "telemetry": {},
            "telemetry_buckets": {},
            "correlation_samples": [],
            "first_seen": None, "last_seen": None,
        },
        # Application error with cross-service corroboration
        "app error": {
            "level": "ERROR", "count": 50,
            "services": ["api", "web", "worker"],
            "correlation": {"pool": ["p1"]},
            "telemetry": {},
            "telemetry_buckets": {},
            "correlation_samples": [{"service": "api", "pool": "p1"}],
            "first_seen": None, "last_seen": None,
        },
    }
    ranked, _ = rank_candidates(issues, [])
    # The corroborated app error should outrank isolated infra warning
    assert ranked[0][0] == "app error", "infrastructure should not auto-win"


def test_unrelated_critical_not_top():
    """A CRITICAL unrelated to the incident should not dominate."""
    from stacksift.diagnostics import rank_candidates

    issues = {
        "unrelated critical": {
            "level": "CRITICAL", "count": 1,
            "services": ["backup"],
            "correlation": {},
            "telemetry": {},
            "telemetry_buckets": {},
            "correlation_samples": [],
            "first_seen": None, "last_seen": None,
        },
        "incident evidence": {
            "level": "WARN", "count": 30,
            "services": ["db", "api"],
            "correlation": {"pool": ["orders"]},
            "telemetry": {"active": {"min": 38, "max": 40}},
            "telemetry_buckets": {
                "2026-10-11T12:30": {"active": {"min": 40, "max": 40, "count": 5}}
            },
            "correlation_samples": [{"service": "db", "pool": "orders"}],
            "first_seen": "2026-10-11T12:30:00.000Z",
            "last_seen": "2026-10-11T12:35:00.000Z",
        },
    }
    ranked, _ = rank_candidates(issues, [])
    # Corroborated evidence should beat isolated CRITICAL
    assert ranked[0][0] == "incident evidence"


def test_section_classification_active_incident():
    """Degradation window + temporally grounded + corroborated = active."""
    from stacksift.diagnostics import classify_incident_section
    evidence = {
        "temporal_alignment": {"score": 3},
        "explanatory_coverage": {"score": 2},
        "resource_pressure": {"score": 0},
        "cross_service": {"score": 0},
        "correlation": {"score": 1},
        "_has_timing": True,
    }
    ranked = [("template", 10.0, evidence)]
    stype, idx = classify_incident_section(ranked, ("12:30", "13:05"))
    assert stype == "active_incident"
    assert idx == 0


def test_section_classification_healthy():
    """No window + weak temporal = none."""
    from stacksift.diagnostics import classify_incident_section
    evidence = {
        "temporal_alignment": {"score": 1},
        "explanatory_coverage": {"score": 0},
        "resource_pressure": {"score": 0},
        "cross_service": {"score": 0},
        "correlation": {"score": 0},
        "_has_timing": True,
    }
    ranked = [("template", 5.0, evidence)]
    stype, idx = classify_incident_section(ranked, None)
    assert stype == "none"


def test_section_classification_missing_timing():
    """Missing timing requires stronger corroboration (adjustment A)."""
    from stacksift.diagnostics import classify_incident_section
    # Strong corroboration (3+ signals) without timing → persistent_failure
    evidence_strong = {
        "temporal_alignment": {"score": 0},
        "explanatory_coverage": {"score": 2},
        "resource_pressure": {"score": 1},
        "cross_service": {"score": 1},
        "correlation": {"score": 1},
        "_has_timing": False,
    }
    ranked = [("template", 8.0, evidence_strong)]
    stype, _ = classify_incident_section(ranked, None)
    assert stype == "persistent_failure"

    # Weak corroboration without timing → none
    # (missing timing is not positive evidence)
    evidence_weak = {
        "temporal_alignment": {"score": 0},
        "explanatory_coverage": {"score": 1},
        "resource_pressure": {"score": 0},
        "cross_service": {"score": 0},
        "correlation": {"score": 0},
        "_has_timing": False,
    }
    ranked = [("template", 5.0, evidence_weak)]
    stype, _ = classify_incident_section(ranked, None)
    assert stype == "none"


def test_possible_contributor_requires_signal():
    """Shared infra alone → correlated, not hypothesized (adjustment B)."""
    from stacksift.diagnostics import _has_contributor_signal
    # Only shared infra, no pressure or specificity → not a contributor
    evidence_bare = {
        "resource_pressure": {"score": 0},
        "specificity": {"score": 0},
    }
    assert not _has_contributor_signal(evidence_bare)
    # With pressure → contributor
    evidence_pressure = {
        "resource_pressure": {"score": 1},
        "specificity": {"score": 0},
    }
    assert _has_contributor_signal(evidence_pressure)


def test_family_grouping_consolidates_variants():
    """Cross-format variants group into families (presentation only)."""
    from stacksift.diagnostics import group_evidence_by_family, _normalize_family
    # Different formats, same event
    assert _normalize_family('{"event": "transaction_hold", "held_ms": 66000}') == "transaction_hold"
    assert _normalize_family('transaction_hold held_ms=66000 pool=orders-primary') == "transaction_hold"
    assert _normalize_family('2026-10-11 WARN [worker] transaction_hold') == "transaction_hold"
    # Different families stay separate
    assert _normalize_family('db_acquire_timeout pool=orders-primary') == "db_acquire"
    assert _normalize_family('checkout failed error_code=TIMEOUT') == "checkout_failure"


def test_family_grouping_preserves_members():
    """All original entries preserved for drill-down."""
    from stacksift.diagnostics import group_evidence_by_family
    items = [
        ("transaction_hold variant A", 10, "WARN", ""),
        ("transaction_hold variant B", 15, "WARN", ""),
        ("db_acquire_timeout", 100, "ERROR", ""),
    ]
    issues = {}  # minimal; telemetry lookup will miss but shouldn't crash
    groups = group_evidence_by_family(items, issues)
    th_group = [g for g in groups if g["family"] == "transaction_hold"][0]
    assert th_group["template_count"] == 2
    assert th_group["total_occurrences"] == 25
    assert len(th_group["members"]) == 2  # both preserved


def test_family_ordering_by_role_not_score():
    """Families ordered by evidence role, not highest member score."""
    from stacksift.diagnostics import group_evidence_by_family
    items = [
        ("checkout_failure x1000", 1000, "ERROR", ""),  # high count, downstream
        ("transaction_hold x5", 5, "WARN", ""),        # low count, contributor
    ]
    groups = group_evidence_by_family(items, {})
    # transaction_hold (possible_contributor, order=1) before checkout (order=4)
    assert groups[0]["family"] == "transaction_hold"
    assert groups[1]["family"] == "checkout_failure"


def test_explain_ranking_returns_list():
    """Regression test for mobile rendering bug.

    The template uses {{ diagnostic_explanation|join(' · ') }}.
    If explain_ranking returns a string, Jinja iterates characters,
    producing S·c·o·r·e·:··3·.·3 — unreadable on mobile.
    Must return a list.
    """
    from stacksift.diagnostics import explain_ranking
    evidence = {
        "temporal_alignment": {"score": 1, "tier": "correlated", "detail": "test detail"},
        "severity": {"score": 0.6, "tier": "observed", "detail": "WARN severity"},
        "_has_timing": True,
    }
    result = explain_ranking("template", 3.3, evidence)
    assert isinstance(result, list), f"must return list, got {type(result).__name__}"
    assert len(result) == 2
    # Simulate Jinja join — must not produce character separation
    joined = " · ".join(result)
    assert "S·c·o·r·e" not in joined
    assert "test detail" in joined


def test_explain_ranking_skips_internal_keys():
    """Internal metadata (_has_timing) must not appear in output."""
    from stacksift.diagnostics import explain_ranking
    evidence = {
        "severity": {"score": 0.6, "tier": "observed", "detail": "WARN"},
        "_has_timing": True,
        "_internal": "should not appear",
    }
    result = explain_ranking("t", 1.0, evidence)
    assert len(result) == 1
    assert result[0] == "WARN"
