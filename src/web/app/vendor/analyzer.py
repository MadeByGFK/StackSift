import re
from collections import Counter
from pathlib import Path

from app.vendor.parser import parse_log_line
from app.vendor.scanner import find_log_files


# --- Structured field extraction (Phase A) --------------------------------
# Extract key=value pairs from messages, preserving original numeric values.
# These survive normalization for diagnostic analysis (Phase C).
# Format: field -> value (numbers as int/float, others as str).

_KV_EXTRACT = re.compile(r'\b([a-z_][a-z0-9_]*)=("[^"]*"|[^\s,)]+)')

# Fields whose distinct values support cross-service correlation.
_CORRELATION_FIELDS = {
    "pool", "db_node", "trace_id", "request_id", "service",
    "node", "host", "instance",
}

# Numeric telemetry fields for resource pressure analysis.
# Others are preserved but not specially tracked.
_TELEMETRY_FIELDS = {
    "active", "idle", "pending", "max_connections",
    "held_ms", "connect_p95_ms", "heap_used_mb", "heap_max_mb",
    "cpu_pct", "queue_depth", "duration_ms",
}


# Maximum correlation samples per issue template (bounded).
# If truncated, the issue gets "correlation_truncated": True.
_MAX_CORRELATION_SAMPLES = 20


def _bucket_key(timestamp: str) -> str | None:
    """5-minute bucket key matching timeline buckets. None if no timestamp."""
    if not timestamp:
        return None
    try:
        # Timestamps are UTC ISO: "2026-10-11T12:03:45.000Z"
        # Bucket to 5-minute: "2026-10-11T12:00"
        date_part, time_part = timestamp.split("T")
        hour, minute = time_part.split(":")[:2]
        bucket_min = (int(minute) // 5) * 5
        return f"{date_part}T{hour}:{bucket_min:02d}"
    except (ValueError, IndexError):
        return None


def extract_structured_fields(message: str) -> dict:
    """Extract key=value fields, preserving numeric types.

    Returns dict of field -> value (int/float for numbers, str otherwise).
    """
    fields = {}
    for key, raw_value in _KV_EXTRACT.findall(message):
        value = raw_value.strip('"')
        # Preserve numeric types
        try:
            if '.' in value:
                fields[key] = float(value)
            else:
                fields[key] = int(value)
        except ValueError:
            fields[key] = value
    return fields


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
    "idempotency_key", "operation_id",
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

_NUMERIC_VALUE = re.compile(r"\b([a-z_][a-z0-9_]*)=(\d+)\b")


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
            # Timestamps are UTC ISO-8601 strings and sort chronologically.
            # Empty timestamps (unstructured notes) are excluded from
            # first/last seen — they go in an unknown-time bucket downstream.
            if entry.timestamp:
                if first_seen is None or entry.timestamp < first_seen:
                    first_seen = entry.timestamp
                if last_seen is None or entry.timestamp > last_seen:
                    last_seen = entry.timestamp
            if entry.service:
                service_counts[entry.service] += 1

            # UNKNOWN severity is counted but not grouped as an issue —
            # we don't fabricate diagnostics from severity-less notes.
            if entry.level in {"WARN", "ERROR", "CRITICAL"}:
                template = normalize_issue(entry.message)
                if template not in issue_counts:
                    issue_counts[template] = {
                        "level": entry.level,
                        "count": 0,
                        # Phase A: structured evidence preserved alongside
                        # the normalized template. Does not affect grouping,
                        # scoring, or ranking — for Phase C diagnostic use.
                        "services": set(),
                        "correlation": {},  # field -> set of distinct values
                        "telemetry": {},    # field -> {"min": x, "max": x}
                        "first_seen": None,
                        "last_seen": None,
                        # Phase A validation: bounded temporal + relationship
                        "telemetry_buckets": {},  # bucket -> field -> {min,max,count}
                        "correlation_samples": [],  # bounded list of relationships
                        "correlation_truncated": False,
                    }

                issue = issue_counts[template]
                issue["count"] += 1

                # Preserve structured evidence (Phase A — no behavior change)
                fields = extract_structured_fields(entry.message)
                if entry.service:
                    issue["services"].add(entry.service)
                for field in _CORRELATION_FIELDS:
                    if field in fields:
                        issue["correlation"].setdefault(field, set()).add(
                            str(fields[field])
                        )
                # Also check entry.service for correlation
                if entry.service:
                    issue["correlation"].setdefault("service", set()).add(
                        entry.service
                    )
                for field in _TELEMETRY_FIELDS:
                    if field in fields and isinstance(fields[field], (int, float)):
                        val = fields[field]
                        rng = issue["telemetry"].setdefault(
                            field, {"min": val, "max": val}
                        )
                        rng["min"] = min(rng["min"], val)
                        rng["max"] = max(rng["max"], val)
                        # Time-bucketed: preserves trend direction
                        bucket = _bucket_key(entry.timestamp)
                        if bucket:
                            bucket_data = issue["telemetry_buckets"].setdefault(
                                bucket, {}
                            )
                            b_rng = bucket_data.setdefault(
                                field, {"min": val, "max": val, "count": 0}
                            )
                            b_rng["min"] = min(b_rng["min"], val)
                            b_rng["max"] = max(b_rng["max"], val)
                            b_rng["count"] += 1
                # Bounded correlation samples: preserve actual relationships
                # between trace_id, service, db_node, and timestamp.
                # Unlike the correlation SETS (which lose relationships),
                # samples show which trace used which node when.
                if len(issue["correlation_samples"]) < _MAX_CORRELATION_SAMPLES:
                    sample = {}
                    for f in ("trace_id", "request_id", "service", "db_node",
                              "pool", "node"):
                        if f in fields:
                            sample[f] = str(fields[f])
                        elif f == "service" and entry.service:
                            sample[f] = entry.service
                    if sample and entry.timestamp:
                        sample["timestamp"] = entry.timestamp
                        # Avoid duplicate samples
                        if sample not in issue["correlation_samples"]:
                            issue["correlation_samples"].append(sample)
                elif not issue["correlation_truncated"]:
                    # Check if there are more distinct relationships
                    issue["correlation_truncated"] = True
                if entry.timestamp:
                    if (issue["first_seen"] is None or
                            entry.timestamp < issue["first_seen"]):
                        issue["first_seen"] = entry.timestamp
                    if (issue["last_seen"] is None or
                            entry.timestamp > issue["last_seen"]):
                        issue["last_seen"] = entry.timestamp

    # Convert sets to sorted lists for JSON serializability.
    # Phase A data is additive — existing consumers see the same
    # level/count fields they always have.
    for issue in issue_counts.values():
        issue["services"] = sorted(issue["services"])
        issue["correlation"] = {
            k: sorted(v) for k, v in issue["correlation"].items()
        }

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
                    "services": set(),
                    "correlation": {},
                    "telemetry": {},
                    "first_seen": None,
                    "last_seen": None,
                    "telemetry_buckets": {},
                    "correlation_samples": [],
                    "correlation_truncated": False,
                }

            combined = combined_issue_counts[message]
            combined["count"] += issue_data["count"]
            # Merge Phase A structured evidence
            combined["services"].update(issue_data.get("services", []))
            for field, values in issue_data.get("correlation", {}).items():
                combined["correlation"].setdefault(field, set()).update(values)
            for field, rng in issue_data.get("telemetry", {}).items():
                existing = combined["telemetry"].setdefault(
                    field, {"min": rng["min"], "max": rng["max"]}
                )
                existing["min"] = min(existing["min"], rng["min"])
                existing["max"] = max(existing["max"], rng["max"])
            # Merge time-bucketed telemetry
            for bucket, fields in issue_data.get("telemetry_buckets", {}).items():
                bucket_data = combined["telemetry_buckets"].setdefault(bucket, {})
                for field, rng in fields.items():
                    existing = bucket_data.setdefault(
                        field, {"min": rng["min"], "max": rng["max"], "count": 0}
                    )
                    existing["min"] = min(existing["min"], rng["min"])
                    existing["max"] = max(existing["max"], rng["max"])
                    existing["count"] += rng.get("count", 0)
            # Merge correlation samples (bounded)
            for sample in issue_data.get("correlation_samples", []):
                if (len(combined["correlation_samples"]) < _MAX_CORRELATION_SAMPLES
                        and sample not in combined["correlation_samples"]):
                    combined["correlation_samples"].append(sample)
            if issue_data.get("correlation_truncated"):
                combined["correlation_truncated"] = True
            fs, ls = issue_data.get("first_seen"), issue_data.get("last_seen")
            if fs and (combined["first_seen"] is None or fs < combined["first_seen"]):
                combined["first_seen"] = fs
            if ls and (combined["last_seen"] is None or ls > combined["last_seen"]):
                combined["last_seen"] = ls

    # Convert sets to sorted lists for JSON serializability
    for issue in combined_issue_counts.values():
        issue["services"] = sorted(issue["services"])
        issue["correlation"] = {
            k: sorted(v) for k, v in issue["correlation"].items()
        }

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