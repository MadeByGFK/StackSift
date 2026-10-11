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
