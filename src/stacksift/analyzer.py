from collections import Counter
from pathlib import Path

from stacksift.parser import parse_log_line
from stacksift.scanner import find_log_files


def analyze_log_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    level_counts = Counter()
    issue_counts = {}
    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            total_lines += 1
            entry = parse_log_line(line)

            if entry is None:
                malformed_lines += 1
                continue

            parsed_lines += 1
            level_counts[entry.level] += 1

            if entry.level in {"WARN", "ERROR", "CRITICAL"}:
                if entry.message not in issue_counts:
                    issue_counts[entry.message] = {
                        "level": entry.level,
                        "count": 0,
                    }

                issue_counts[entry.message]["count"] += 1

    return {
        "file": str(path),
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "malformed_lines": malformed_lines,
        "level_counts": dict(level_counts),
        "issues": issue_counts,
    }


def analyze_path(input_path: str) -> dict:
    path = Path(input_path)
    log_files = find_log_files(path)

    if not log_files:
        raise FileNotFoundError(f"No .log files found at: {input_path}")

    combined_level_counts = Counter()
    combined_issue_counts = {}
    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0
    scanned_files = []

    for log_file in log_files:
        results = analyze_log_file(str(log_file))

        scanned_files.append(results["file"])
        total_lines += results["total_lines"]
        parsed_lines += results["parsed_lines"]
        malformed_lines += results["malformed_lines"]
        combined_level_counts.update(results["level_counts"])
        
        for message, issue_data in results["issues"].items():
            if message not in combined_issue_counts:
                combined_issue_counts[message] = {
                    "level": issue_data["level"],
                    "count": 0,
                }

            combined_issue_counts[message]["count"] += issue_data["count"]

    return {
        "file": str(path),
        "scanned_files": scanned_files,
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "malformed_lines": malformed_lines,
        "level_counts": dict(combined_level_counts),
        "issues": combined_issue_counts,
    }