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
    level_counts = {
        "INFO": 10,
        "WARN": 2,
        "ERROR": 1,
        "CRITICAL": 0,
    }

    assert determine_health(level_counts) == ("Healthy", "green")


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