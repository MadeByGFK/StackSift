from datetime import datetime

from stacksift.insights import (
    build_timeline,
    diagnostic_score,
    most_diagnostic_issue,
)


def _issues():
    return {
        "connection_acquire_wait": {"level": "WARN", "count": 522},
        "transaction_watchdog idle_in_transaction": {"level": "ERROR", "count": 1},
        "http_request status=500": {"level": "ERROR", "count": 317},
    }


def test_diagnostic_beats_frequent():
    diag = most_diagnostic_issue(_issues())
    assert diag is not None
    assert "watchdog" in diag[0]


def test_empty_issues_returns_none():
    assert most_diagnostic_issue({}) is None


def test_keyword_boost():
    plain = diagnostic_score("ERROR", "something failed", 1)
    keyword = diagnostic_score("ERROR", "watchdog idle_in_transaction leak", 1)
    assert keyword > plain


def test_severity_weight():
    warn = diagnostic_score("WARN", "idle_in_transaction", 1)
    error = diagnostic_score("ERROR", "idle_in_transaction", 1)
    assert error > warn


def test_timeline_buckets_and_phases():
    base = datetime(2026, 10, 10, 14, 0, 0)
    events = []
    # quiet baseline: 2 events in first bucket
    events += [("2026-10-10 14:01:00", "INFO")] * 2
    # spike: 50 errors in the 14:10 bucket
    events += [("2026-10-10 14:10:00", "ERROR")] * 50
    # quiet again
    events += [("2026-10-10 14:20:00", "INFO")] * 2

    tl = build_timeline(events, bucket_minutes=5)
    assert len(tl) >= 3
    phases = {b["label"]: b["phase"] for b in tl}
    # the spike bucket should be peak, surroundings baseline
    peak_buckets = [b for b in tl if b["phase"] == "peak"]
    assert len(peak_buckets) == 1
    assert peak_buckets[0]["error"] == 50


def test_timeline_empty():
    assert build_timeline([]) == []


def test_timeline_single_bucket():
    tl = build_timeline([("2026-10-10 14:01:00", "ERROR")])
    assert len(tl) == 1
