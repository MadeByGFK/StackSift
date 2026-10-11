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


def test_failure_value_signal_is_domain_general():
    # No database keywords — an auth/cert failure should still rank up.
    from stacksift.insights import diagnostic_score
    generic = diagnostic_score("ERROR", "cert_validator status=expired", 2)
    plain = diagnostic_score("ERROR", "request failed", 2)
    assert generic > plain


def test_failure_value_in_reasons():
    from stacksift.insights import diagnostic_reasons
    reasons = " ".join(
        diagnostic_reasons("WARN", "conn_holder release_observed=false", 1)
    ).lower()
    assert "false" in reasons


def test_declining_not_recovering():
    tl = build_timeline([
        ("2026-10-10 14:01:00", "ERROR"),
    ] * 5 + [
        ("2026-10-10 14:10:00", "ERROR"),
    ] * 50 + [
        ("2026-10-10 14:20:00", "ERROR"),
    ] * 10)
    phases = {b["phase"] for b in tl}
    assert "declining" in phases
    assert "recovering" not in phases


def test_field_aware_signal_cert_beats_notification():
    # Benchmark #2: certificate failure must outrank unrelated
    # notification failure even though both are rare ERRORs.
    from stacksift.insights import most_diagnostic_issue
    from stacksift.analyzer import normalize_issue
    issues = {
        normalize_issue("[notification-service] delivery_failed reason=recipient_rejected retryable=false"): {"level": "ERROR", "count": 1},
        normalize_issue("[auth-service] certificate_check_failed verification=X509_V_ERR_CERT_HAS_EXPIRED"): {"level": "ERROR", "count": 1},
    }
    diag = most_diagnostic_issue(issues)
    assert "certificate_check_failed" in diag[0]


def test_retryable_false_is_not_diagnostic():
    # retryable=false is metadata ("don't retry"), not a diagnosis.
    from stacksift.insights import diagnostic_score
    s = diagnostic_score("ERROR", "delivery_failed retryable=false", 1)
    assert s < diagnostic_score(
        "ERROR", "certificate_check_failed verification=X509_V_ERR_CERT_HAS_EXPIRED", 1)


def test_field_name_id_normalization():
    # Benchmark #2: rq-02-0000 format must group like req-12345 did.
    from stacksift.analyzer import normalize_issue
    m1 = "token_validation_failed request_id=rq-02-0021 node=auth-a reason=x"
    m2 = "token_validation_failed request_id=rq-02-0022 node=auth-a reason=x"
    n1, n2 = normalize_issue(m1), normalize_issue(m2)
    assert n1 == n2
    assert "rq-02" not in n1
    # meaningful values preserved
    assert "reason=x" in n1


def test_timestamp_values_normalized():
    from stacksift.analyzer import normalize_issue
    m1 = "token_validation_failed token_exp=2026-07-10T15:00:00.000Z reason=x"
    m2 = "token_validation_failed token_exp=2026-07-11T15:00:00.000Z reason=x"
    assert normalize_issue(m1) == normalize_issue(m2)


def test_numeric_fields_with_digits_normalize():
    # Benchmark #4: p95/p99-style telemetry fields contain digits and
    # must normalize like any other numeric field.
    from stacksift.analyzer import normalize_issue
    m1 = "event=path_probe connect_p95_ms=983 rtt_ms=12"
    m2 = "event=path_probe connect_p95_ms=1189 rtt_ms=45"
    n1, n2 = normalize_issue(m1), normalize_issue(m2)
    assert n1 == n2
    assert "connect_p95_ms=<n>" in n1
    # HTTP status still preserved
    assert "status=500" in normalize_issue("request_failed status=500")


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


def test_health_stable_activity_no_escalation():
    # Benchmark #5: flat 72-81 warnings/errors per bucket, no incident.
    from stacksift.insights import determine_health
    buckets = [79, 81, 79, 78, 77, 75, 75, 79, 80, 77, 78, 77, 77, 78, 79, 80, 79, 72]
    label, color = determine_health({"WARN": 1200, "ERROR": 200}, buckets)
    assert label == "No Escalation Detected", label
    assert color == "green"


def test_health_sustained_strong_escalation():
    # Clear incident: baseline ~65, sustained 3x+ spike.
    from stacksift.insights import determine_health
    buckets = [65, 65, 166, 266, 366, 465, 416, 240, 115, 65, 65]
    label, color = determine_health({"WARN": 1034, "ERROR": 1037}, buckets)
    assert label == "Elevated Incident Activity", label
    assert color == "red"


def test_health_sustained_moderate_escalation():
    from stacksift.insights import determine_health
    buckets = [50, 52, 48, 110, 120, 105, 55, 50]
    label, _ = determine_health({"WARN": 200, "ERROR": 50}, buckets)
    assert label == "Increased Error Activity", label


def test_health_isolated_spike_not_incident():
    # Single spike must not qualify as sustained escalation.
    from stacksift.insights import determine_health
    buckets = [60, 62, 58, 300, 61, 59, 63]
    label, _ = determine_health({"WARN": 300, "ERROR": 50}, buckets)
    assert label == "No Escalation Detected", label


def test_health_sparse_data_undetermined():
    # 1 -> 7 is 7x but meaningless without volume.
    from stacksift.insights import determine_health
    label, color = determine_health({"WARN": 8}, [1, 7, 2])
    assert label == "Health Undetermined", label
    assert color == "gray"


def test_health_too_few_buckets():
    from stacksift.insights import determine_health
    label, _ = determine_health({"WARN": 50}, [30, 40])
    assert label == "Health Undetermined"


def test_health_no_issues():
    from stacksift.insights import determine_health
    label, color = determine_health({}, [0, 0, 0, 0])
    assert label == "No Significant Issues Detected"
    assert color == "green"


def test_health_critical_overrides():
    from stacksift.insights import determine_health
    label, color = determine_health({"CRITICAL": 1}, [10, 10, 10])
    assert label == "Critical"
    assert color == "red"
