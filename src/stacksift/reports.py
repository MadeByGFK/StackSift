from pathlib import Path

from stacksift.insights import (
    sort_issues_by_severity,
)


def save_report(results: dict) -> str:
    report_path = Path("reports") / "summary.txt"
    report_path.parent.mkdir(exist_ok=True)

    lines = [
        "StackSift Summary",
        "",
        f"File: {results['file']}",
        f"Total lines: {results['total_lines']}",
        f"Parsed lines: {results['parsed_lines']}",
        "",
        "Log Levels:",
    ]

    for level, count in results["level_counts"].items():
        lines.append(f"- {level}: {count}")

    lines.append("")
    lines.append("Issues:")

    sorted_issues = sort_issues_by_severity(results["issues"])

    for issue, data in sorted_issues:
        lines.append(f"- [{data['level']}] {issue}: {data['count']}")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return str(report_path)