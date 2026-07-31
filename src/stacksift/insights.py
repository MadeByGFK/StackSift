SEVERITY_ORDER = {
    "CRITICAL": 0,
    "ERROR": 1,
    "WARN": 2,
    "INFO": 3,
}


def determine_health(level_counts: dict) -> tuple[str, str]:
    critical = level_counts.get("CRITICAL", 0)
    errors = level_counts.get("ERROR", 0)
    warnings = level_counts.get("WARN", 0)

    if critical > 0:
        return ("Critical", "red")

    if errors >= 10:
        return ("High Error Activity", "yellow")

    if warnings >= 20:
        return ("Elevated Activity", "yellow")

    return ("Healthy", "green")


def most_frequent_issue(issues: dict):
    if not issues:
        return None

    return max(
        issues.items(),
        key=lambda item: item[1]["count"]
    )

def sort_issues_by_severity(issues: dict) -> list:
    """
    Sort issues by severity first, then by occurrence count.
    """

    return sorted(
        issues.items(),
        key=lambda item: (
            SEVERITY_ORDER.get(item[1]["level"], 99),
            -item[1]["count"],
        ),
    )