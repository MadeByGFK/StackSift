from collections import Counter
from pathlib import Path

from stacksift.parser import parse_log_line


def analyze_log_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    level_counts = Counter()
    message_counts = Counter()
    total_lines = 0
    parsed_lines = 0

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            total_lines += 1
            entry = parse_log_line(line)

            if entry is None:
                continue

            parsed_lines += 1
            level_counts[entry.level] += 1

            if entry.level in {"ERROR", "CRITICAL"}:
                message_counts[entry.message] += 1

    return {
        "file": str(path),
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "level_counts": dict(level_counts),
        "top_issues": message_counts.most_common(5),
    }

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
    lines.append("Top Issues:")

    for issue, count in results["top_issues"]:
        lines.append(f"- {issue}: {count}")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return str(report_path)