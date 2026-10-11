from stacksift.insights import (
    determine_health,
    most_frequent_issue,
    sort_issues_by_severity,
)


def test_determine_health_is_critical():
    level_counts = {
        "INFO": 5,
        "WARN": 2,
        "ERROR": 3,
        "CRITICAL": 1,
    }

    assert determine_health(level_counts) == ("Critical", "red")


def test_determine_health_is_healthy():
    # No warnings/errors at all -> nothing significant detected.
    level_counts = {
        "INFO": 10,
        "WARN": 0,
        "ERROR": 0,
        "CRITICAL": 0,
    }

    assert determine_health(level_counts, [0, 0, 0, 0]) == (
        "No Significant Issues Detected",
        "green",
    )


def test_determine_health_undetermined_without_timeline():
    # Old callers without bucket data get an honest "undetermined".
    level_counts = {"INFO": 10, "WARN": 2, "ERROR": 1, "CRITICAL": 0}

    assert determine_health(level_counts) == ("Health Undetermined", "gray")


def test_most_frequent_issue():
    issues = {
        "Database timeout": {
            "level": "ERROR",
            "count": 4,
        },
        "API unavailable": {
            "level": "CRITICAL",
            "count": 2,
        },
    }

    message, data = most_frequent_issue(issues)

    assert message == "Database timeout"
    assert data["count"] == 4


def test_sort_issues_by_severity_then_count():
    issues = {
        "Minor warning": {
            "level": "WARN",
            "count": 20,
        },
        "Database timeout": {
            "level": "ERROR",
            "count": 5,
        },
        "Application shutdown": {
            "level": "CRITICAL",
            "count": 1,
        },
        "Authentication failure": {
            "level": "ERROR",
            "count": 8,
        },
    }

    sorted_issues = sort_issues_by_severity(issues)

    assert [message for message, _ in sorted_issues] == [
        "Application shutdown",
        "Authentication failure",
        "Database timeout",
        "Minor warning",
    ]

def test_operation_id_normalization_groups_related_events():
    """Phase B regression: operation_id is a correlation identifier, not an
    event discriminator. Different operation_id values for the same event
    type must group together; different event types must stay separate."""
    from stacksift.analyzer import normalize_issue

    # Same event, different operation_ids -> same template
    t1 = normalize_issue(
        "event=network_retry operation_id=noise-000000 reason=timeout"
    )
    t2 = normalize_issue(
        "event=network_retry operation_id=noise-000001 reason=timeout"
    )
    assert t1 == t2, f"operation_id not normalized: {t1} != {t2}"
    assert "operation_id=<id>" in t1

    # Different events, same operation_id -> different templates
    t3 = normalize_issue(
        "event=network_retry operation_id=noise-000000 reason=timeout"
    )
    t4 = normalize_issue(
        "event=network_retry_resolved operation_id=noise-000000 result=success"
    )
    assert t3 != t4, "distinct event types were merged!"


def test_structured_fields_survive_normalization():
    """Phase A: numeric telemetry values must survive grouping.
    Two events with different values group together, but the original
    values remain available for diagnostic analysis."""
    from stacksift.analyzer import analyze_log_file
    import tempfile, os

    content = (
        "2026-10-11T12:00:00Z WARN [db] pool sample | "
        "service=database-service pool=orders-primary active=40 idle=60 max_connections=100\n"
        "2026-10-11T12:05:00Z WARN [db] pool sample | "
        "service=database-service pool=orders-primary active=95 idle=5 max_connections=100\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
        tmp.write(content)
        path = tmp.name
    try:
        r = analyze_log_file(path)
        assert len(r["issues"]) == 1, "should group into one template"
        issue = list(r["issues"].values())[0]
        assert issue["count"] == 2
        # Original values preserved
        assert issue["telemetry"]["active"]["min"] == 40
        assert issue["telemetry"]["active"]["max"] == 95
        assert issue["telemetry"]["idle"]["min"] == 5
        assert issue["telemetry"]["idle"]["max"] == 60
        # Correlation preserved
        assert "orders-primary" in issue["correlation"]["pool"]
    finally:
        os.unlink(path)


def test_missing_fields_stay_missing():
    """Phase A: absent fields are not fabricated."""
    from stacksift.analyzer import analyze_log_file
    import tempfile, os

    content = "2026-10-11T12:00:00Z WARN [db] something broke | service=db\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
        tmp.write(content)
        path = tmp.name
    try:
        r = analyze_log_file(path)
        issue = list(r["issues"].values())[0]
        # No telemetry fields present -> empty dict, not fabricated values
        assert issue["telemetry"] == {}
        # Service is preserved
        assert "db" in issue["services"]
    finally:
        os.unlink(path)


def test_issue_timestamps_preserved():
    """Phase A: first/last seen per issue template."""
    from stacksift.analyzer import analyze_log_file
    import tempfile, os

    content = (
        "2026-10-11T12:00:00Z WARN [s] evt | service=s event=e\n"
        "2026-10-11T12:10:00Z WARN [s] evt | service=s event=e\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
        tmp.write(content)
        path = tmp.name
    try:
        r = analyze_log_file(path)
        issue = list(r["issues"].values())[0]
        assert issue["first_seen"] == "2026-10-11T12:00:00.000Z"
        assert issue["last_seen"] == "2026-10-11T12:10:00.000Z"
    finally:
        os.unlink(path)


def test_telemetry_buckets_distinguish_trend_direction():
    """Phase A validation: time-bucketed telemetry must distinguish
    degradation (rising) from recovery (falling) even when min/max
    aggregates are identical."""
    from stacksift.analyzer import analyze_log_file
    import tempfile, os

    def make_log(values):
        lines = []
        for i, pending in enumerate(values):
            t = f"12:{i*5:02d}:00"
            lines.append(
                f"2026-10-11T{t}Z WARN [db] pool | "
                f"service=db pool=p active=40 pending={pending}\n"
            )
        return "".join(lines)

    # Same min/max (9/94), opposite directions
    degradation = [9, 20, 50, 94]
    recovery = [94, 50, 20, 9]

    results = {}
    for name, values in [("deg", degradation), ("rec", recovery)]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
            tmp.write(make_log(values))
            path = tmp.name
        try:
            r = analyze_log_file(path)
            issue = list(r["issues"].values())[0]
            buckets = issue["telemetry_buckets"]
            # Extract pending values in chronological order
            ordered = [buckets[k]["pending"]["max"] for k in sorted(buckets.keys())]
            results[name] = ordered
        finally:
            os.unlink(path)

    assert results["deg"] == [9, 20, 50, 94], "degradation trend lost"
    assert results["rec"] == [94, 50, 20, 9], "recovery trend lost"
    assert results["deg"] != results["rec"], "cannot distinguish trends!"


def test_correlation_samples_preserve_relationships():
    """Phase A validation: correlation samples must preserve which
    trace_id used which db_node, not just that both values appeared."""
    from stacksift.analyzer import analyze_log_file
    import tempfile, os

    content = (
        "2026-10-11T12:00:00Z WARN [s] evt | service=order-service "
        "trace_id=trace-A db_node=db-01 event=e\n"
        "2026-10-11T12:01:00Z WARN [s] evt | service=payment-service "
        "trace_id=trace-B db_node=db-02 event=e\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
        tmp.write(content)
        path = tmp.name
    try:
        r = analyze_log_file(path)
        issue = list(r["issues"].values())[0]
        samples = issue["correlation_samples"]
        # Find the sample linking trace-A to db-01
        trace_a = [s for s in samples if s.get("trace_id") == "trace-A"]
        assert len(trace_a) == 1, "trace-A relationship lost"
        assert trace_a[0]["db_node"] == "db-01", "wrong node for trace-A"
        assert trace_a[0]["service"] == "order-service"
    finally:
        os.unlink(path)
