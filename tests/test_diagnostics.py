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
