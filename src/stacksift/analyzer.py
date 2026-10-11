import re
from collections import Counter
from pathlib import Path

from stacksift.parser import parse_log_line
from stacksift.scanner import find_log_files


# --- Issue normalization for grouping -------------------------------------
# Repeated event templates vary by IDs, durations, and counters. Normalize
# those so they cluster; keep semantically meaningful values (notably HTTP
# status, error reasons, paths) intact so 500s and 503s stay distinguishable.
#
# ID normalization is field-name-based, not value-pattern-based: any
# request_id=, trace_id=, etc. gets normalized regardless of the ID format
# (req-abc, rq-02-0000, uuid, ...). Value patterns are only a fallback.

_ID_FIELDS = {
    "request_id", "trace_id", "span_id", "correlation_id", "session_id",
    "connection_id", "order_id", "user_id", "client_id", "device_id",
    "idempotency_key",
}

# Fields that identify WHERE something happened (hosts, nodes, instances).
# Never normalized — collapsing ord-01/ord-02 would hide which node failed.
_PRESERVE_FIELDS = {
    "node", "host", "hostname", "instance", "pod", "container",
}

_ID_SUBS = [
    (re.compile(r"\breq-[a-f0-9]+\b"), "req-<id>"),
    (re.compile(r"\b[a-f0-9]{16,}\b"), "<hex>"),
]

# Timestamps embedded in values (e.g. token_exp=2026-10-11T15:00:00.000Z).
_TS_VALUE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^,\s)]*")

_NUMERIC_VALUE = re.compile(r"\b([a-z_]+)=(\d+)\b")


def _keep_or_normalize(match: re.Match) -> str:
    # HTTP status codes are diagnostically meaningful — keep them.
    if match.group(1) == "status":
        return match.group(0)
    return f"{match.group(1)}=<n>"


def normalize_issue(message: str) -> str:
    """Return the grouping template for a log message."""
    msg = message
    # 1. Field-name-based: normalize the VALUE of known identifier fields,
    #    except fields that identify where it happened (node, host, ...).
    for field in _ID_FIELDS:
        if field in _PRESERVE_FIELDS:
            continue
        msg = re.sub(rf"\b{field}=[^\s,)]+", f"{field}=<id>", msg)
    # 2. Timestamps embedded in values.
    msg = _TS_VALUE.sub("<ts>", msg)
    # 3. Fallback: value-pattern-based ID shapes.
    for pattern, replacement in _ID_SUBS:
        msg = pattern.sub(replacement, msg)
    # 4. Numeric values (except HTTP status).
    msg = _NUMERIC_VALUE.sub(_keep_or_normalize, msg)
    return msg


def analyze_log_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    level_counts = Counter()
    service_counts = Counter()
    issue_counts = {}
    events = []
    first_seen = None
    last_seen = None
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
            events.append((entry.timestamp, entry.level))
            # Timestamps sort chronologically as strings in both
            # supported formats (ISO-8601 and "YYYY-MM-DD HH:MM:SS").
            if first_seen is None or entry.timestamp < first_seen:
                first_seen = entry.timestamp
            if last_seen is None or entry.timestamp > last_seen:
                last_seen = entry.timestamp
            if entry.service:
                service_counts[entry.service] += 1

            if entry.level in {"WARN", "ERROR", "CRITICAL"}:
                template = normalize_issue(entry.message)
                if template not in issue_counts:
                    issue_counts[template] = {
                        "level": entry.level,
                        "count": 0,
                    }

                issue_counts[template]["count"] += 1

    return {
        "file": str(path),
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "malformed_lines": malformed_lines,
        "level_counts": dict(level_counts),
        "service_counts": dict(service_counts),
        "issues": issue_counts,
        "events": events,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def analyze_path(input_path: str) -> dict:
    path = Path(input_path)
    log_files = find_log_files(path)

    if not log_files:
        raise FileNotFoundError(f"No .log files found at: {input_path}")

    combined_level_counts = Counter()
    combined_service_counts = Counter()
    combined_issue_counts = {}
    combined_events = []
    first_seen = None
    last_seen = None
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
        combined_service_counts.update(results.get("service_counts", {}))
        combined_events.extend(results.get("events", []))
        fs, ls = results.get("first_seen"), results.get("last_seen")
        if fs and (first_seen is None or fs < first_seen):
            first_seen = fs
        if ls and (last_seen is None or ls > last_seen):
            last_seen = ls
        
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
        "service_counts": dict(combined_service_counts),
        "issues": combined_issue_counts,
        "events": combined_events,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }