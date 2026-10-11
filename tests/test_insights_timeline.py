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


def test_timeline_skips_unparseable_timestamps():
    events = [
        ("not-a-timestamp", "ERROR"),
        ("2026-10-10 14:01:00", "ERROR"),
        ("", "WARN"),
    ]
    tl = build_timeline(events)
    assert len(tl) == 1
    assert tl[0]["error"] == 1


def test_timeline_no_timestamps_at_all():
    assert build_timeline([("garbage", "ERROR"), ("", "WARN")]) == []


def test_isolated_diagnostic_event_wins():
    issues = {
        "connection_acquire_wait": {"level": "WARN", "count": 522},
        "http_request status=500": {"level": "ERROR", "count": 317},
        "transaction_watchdog idle_in_transaction": {"level": "ERROR", "count": 1},
    }
    diag = most_diagnostic_issue(issues)
    assert diag is not None
    assert "watchdog" in diag[0]
    # and the frequent issue is still the frequent one
    from stacksift.insights import most_frequent_issue
    freq = most_frequent_issue(issues)
    assert "connection_acquire_wait" in freq[0]


def test_diagnostic_reasons_explainable():
    from stacksift.insights import diagnostic_reasons
    reasons = diagnostic_reasons(
        "ERROR", "transaction_watchdog idle_in_transaction leak", 1
    )
    text = " ".join(reasons).lower()
    assert "error" in text
    assert "idle_in_transaction" in text
    assert "1 occurrence" in text


def test_rarity_alone_does_not_dominate():
    # A single noisy INFO-ish warning should not outrank a frequent ERROR.
    noisy = diagnostic_score("WARN", "something odd happened", 1)
    frequent_error = diagnostic_score("ERROR", "connection timeout", 500)
    assert frequent_error > noisy


def test_first_last_seen():
    from stacksift.analyzer import analyze_log_file
    import tempfile, os
    content = (
        "2026-10-10 14:05:00 INFO middle\n"
        "2026-10-10 14:01:00 WARN early\n"
        "2026-10-10 14:09:00 ERROR late\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False
    ) as tmp:
        tmp.write(content)
        path = tmp.name
    try:
        r = analyze_log_file(path)
        assert r["first_seen"] == "2026-10-10 14:01:00"
        assert r["last_seen"] == "2026-10-10 14:09:00"
    finally:
        os.unlink(path)
