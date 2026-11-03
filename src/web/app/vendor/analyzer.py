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

# --- Issue #106 Stage 1: grouping version, peak severity, evidence -------
# F01/F04/F05 are CORE correctness fixes (approved #106 spec, Stage 1):
# they change the grouping template and the recorded group level for
# standard and premium output alike. GROUPING_VERSION identifies the
# corrected grouping so retained evidence can name the rules it was
# captured under.
GROUPING_VERSION = "106-stage1-v1"
DIAGNOSTIC_EVIDENCE_SCHEMA_VERSION = 1

_LEVEL_RANK = {"WARN": 0, "ERROR": 1, "CRITICAL": 2}


def _peak_level(a: str, b: str) -> str:
    """Highest of two severities under WARN < ERROR < CRITICAL (F04)."""
    return a if _LEVEL_RANK.get(a, -1) >= _LEVEL_RANK.get(b, -1) else b


# Retained diagnostic-evidence bounds (#106 Stage 1). Excerpt sampling
# starts from the comparison collector's policy: at most 2 excerpts per
# observed severity per group, each at most 1,024 characters.
MAX_DIAGNOSTIC_EVIDENCE_GROUPS = 1000
MAX_DIAGNOSTIC_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_DIAGNOSTIC_EXCERPTS_PER_LEVEL = 2
MAX_DIAGNOSTIC_EXCERPT_CHARS = 1024


def _enforce_evidence_size(evidence: dict) -> None:
    """Trim retained evidence in place to the serialized-size bound.

    Excerpts are dropped first (newest group, newest excerpt); whole
    groups are dropped only when no excerpts remain. Every trim is
    disclosed via the evidence truncation flags — never silently.
    """
    import json as _json

    groups = evidence["groups"]
    while groups and len(_json.dumps(evidence).encode("utf-8")) > \
            MAX_DIAGNOSTIC_EVIDENCE_BYTES:
        trimmed = False
        for template in reversed(list(groups)):
            if groups[template]["excerpts"]:
                groups[template]["excerpts"].pop()
                groups[template]["excerpts_truncated"] = True
                trimmed = True
                break
        if not trimmed:
            groups.popitem()
            evidence["groups_truncated"] = True
        evidence["truncated"] = True


class _DiagnosticEvidenceBuilder:
    """Bounded retained-evidence capture at the parse/group point.

    Generalizes the opt-in comparison collector (#102): the same branch
    that groups an entry records, for the corrected template, the
    per-severity observed counts and bounded redacted excerpts of the
    analysis lines that produced the group. Lines fed to the analyzer
    are the prepared (redacted, JSON-lines-adapted) analysis lines, so
    excerpt coordinates are labeled "analysis line" — they are not
    claimed to be original physical source lines.
    """

    def __init__(self) -> None:
        self.groups: dict = {}
        self.groups_truncated = False
        self._seq = 0

    def record(self, template, level, line_number, raw_text,
               timestamp, service) -> None:
        group = self.groups.get(template)
        if group is None:
            if len(self.groups) >= MAX_DIAGNOSTIC_EVIDENCE_GROUPS:
                self.groups_truncated = True
                return
            group = {
                "level_counts": {},
                "peak_level": level,
                "excerpts": [],
                "excerpts_truncated": False,
                "_captured": {},
            }
            self.groups[template] = group
        group["level_counts"][level] = group["level_counts"].get(level, 0) + 1
        group["peak_level"] = _peak_level(group["peak_level"], level)
        captured = group["_captured"].get(level, 0)
        if captured >= MAX_DIAGNOSTIC_EXCERPTS_PER_LEVEL:
            group["excerpts_truncated"] = True
            return
        text = raw_text
        text_truncated = False
        if len(text) > MAX_DIAGNOSTIC_EXCERPT_CHARS:
            text = text[:MAX_DIAGNOSTIC_EXCERPT_CHARS]
            text_truncated = True
            group["excerpts_truncated"] = True
        group["_captured"][level] = captured + 1
        self._seq += 1
        group["excerpts"].append({
            "evidence_id": f"ev-{self._seq:06d}",
            "level": level,
            "analysis_line_number": line_number,
            "text": text,
            "text_truncated": text_truncated,
            "timestamp": timestamp,
            "service": service,
        })

    def build(self) -> dict:
        groups = {}
        truncated = self.groups_truncated
        for template, group in self.groups.items():
            if group["excerpts_truncated"]:
                truncated = True
            groups[template] = {
                "level_counts": dict(group["level_counts"]),
                "peak_level": group["peak_level"],
                "excerpts": [dict(e) for e in group["excerpts"]],
                "excerpts_truncated": group["excerpts_truncated"],
            }
        evidence = {
            "schema_version": DIAGNOSTIC_EVIDENCE_SCHEMA_VERSION,
            "grouping_version": GROUPING_VERSION,
            "coordinate": "analysis line",
            "groups": groups,
            "groups_truncated": self.groups_truncated,
            "truncated": truncated,
        }
        _enforce_evidence_size(evidence)
        return evidence


def _merge_diagnostic_evidence(evidences) -> dict:
    """Merge per-file diagnostic evidence (analyze_path cross-file leg).

    Severity counts sum, peak levels merge by peak, excerpts keep the
    per-severity capture cap, and evidence IDs are re-sequenced so the
    merged artifact carries stable, unique IDs. Analysis-line numbers
    remain coordinates within their own source file.
    """
    groups: dict = {}
    groups_truncated = False
    truncated = False
    seq = 0
    for ev in evidences:
        if not ev:
            continue
        groups_truncated = groups_truncated or bool(ev.get("groups_truncated"))
        truncated = truncated or bool(ev.get("truncated"))
        for template, group in ev.get("groups", {}).items():
            combined = groups.get(template)
            if combined is None:
                if len(groups) >= MAX_DIAGNOSTIC_EVIDENCE_GROUPS:
                    groups_truncated = True
                    truncated = True
                    continue
                combined = {
                    "level_counts": {},
                    "peak_level": group["peak_level"],
                    "excerpts": [],
                    "excerpts_truncated": False,
                    "_captured": {},
                }
                groups[template] = combined
            for lvl, count in group["level_counts"].items():
                combined["level_counts"][lvl] = (
                    combined["level_counts"].get(lvl, 0) + count)
            combined["peak_level"] = _peak_level(
                combined["peak_level"], group["peak_level"])
            combined["excerpts_truncated"] = (
                combined["excerpts_truncated"]
                or bool(group.get("excerpts_truncated")))
            for excerpt in group["excerpts"]:
                lvl = excerpt["level"]
                if combined["_captured"].get(lvl, 0) >= \
                        MAX_DIAGNOSTIC_EXCERPTS_PER_LEVEL:
                    combined["excerpts_truncated"] = True
                    continue
                combined["_captured"][lvl] = \
                    combined["_captured"].get(lvl, 0) + 1
                seq += 1
                merged_excerpt = dict(excerpt)
                merged_excerpt["evidence_id"] = f"ev-{seq:06d}"
                combined["excerpts"].append(merged_excerpt)
    out_groups = {}
    for template, group in groups.items():
        if group["excerpts_truncated"]:
            truncated = True
        out_groups[template] = {
            "level_counts": dict(group["level_counts"]),
            "peak_level": group["peak_level"],
            "excerpts": group["excerpts"],
            "excerpts_truncated": group["excerpts_truncated"],
        }
    evidence = {
        "schema_version": DIAGNOSTIC_EVIDENCE_SCHEMA_VERSION,
        "grouping_version": GROUPING_VERSION,
        "coordinate": "analysis line",
        "groups": out_groups,
        "groups_truncated": groups_truncated,
        "truncated": truncated,
    }
    _enforce_evidence_size(evidence)
    return evidence



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


# F05 (#106): the anchored request-handler wrapper, stripped ONLY when
# the remainder is a recognized exception-bearing cause (an exception
# type ending in Error/Exception/Fault/Timeout followed by ":"). Other
# wrappers and other causes keep their literal identity.
_WRAPPER_PREFIX = "Request handler failed: "
_EXCEPTION_CAUSE = re.compile(
    r"^[A-Z][A-Za-z0-9_]*(?:Error|Exception|Fault|Timeout):")

# F01 (#106): a volatile BARE order identifier — the word "order"
# followed by a bare number with no field name (``order 58291``). This
# is deliberately contextual: numbers anywhere else (status codes,
# host/node names, ports, counts) are NOT touched by this rule.
_BARE_ORDER_ID = re.compile(r"\border \d+\b")


def normalize_issue(message: str) -> str:
    """Return the grouping template for a log message."""
    msg = message
    # 0a. F05: unwrap the anchored request-handler wrapper when it wraps
    #     a recognized exception-bearing cause, so the wrapped and bare
    #     forms of the same failure share one group identity. Occurrence
    #     totals are preserved — this is grouping, not deduplication.
    if msg.startswith(_WRAPPER_PREFIX):
        cause = msg[len(_WRAPPER_PREFIX):]
        if _EXCEPTION_CAUSE.match(cause):
            msg = cause
    # 0b. F01: normalize volatile bare order identifiers in context.
    msg = _BARE_ORDER_ID.sub("order <id>", msg)
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


def analyze_log_file(file_path: str, *, collect_comparison_evidence: bool = False) -> dict:
    """Analyze one log file.

    Issue #102 (comparison v1): when ``collect_comparison_evidence`` is
    true, the result gains an additive ``comparison_evidence`` key, keyed
    by the same normalized template as ``issues``. Each entry carries the
    per-severity level distribution (the stored group's ``level`` is the
    peak level since #106 and cannot show the full distribution) and up
    to 2 example lines per observed severity, each truncated to 1,024
    characters. When the flag is false (the default), the result shape is
    exactly the historical one — no extra key, no behavior change. The
    caller is responsible for feeding this function the prepared
    (redacted, JSON-lines-adapted) text, so recorded example lines are
    redacted analysis lines, never raw uploads.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    level_counts = Counter()
    service_counts = Counter()
    issue_counts = {}
    # Issue #102 evidence collector (default OFF, additive only).
    comparison_evidence: dict = {} if collect_comparison_evidence else None
    # Issue #106 Stage 1: retained diagnostic evidence, always captured
    # for new analyses (additive key; see _DiagnosticEvidenceBuilder).
    diagnostic_evidence = _DiagnosticEvidenceBuilder()
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
                # F04 (#106): the group's recorded level is the PEAK
                # observed severity, not the first-seen one. Individual
                # level_counts and occurrence counts are unchanged and
                # source events are never relabeled.
                issue["level"] = _peak_level(issue["level"], entry.level)
                # #106 Stage 1: retained diagnostic evidence, recorded
                # at this same parse/group point so every excerpt maps
                # to the corrected issue key and an actual processed
                # (redacted analysis) line.
                diagnostic_evidence.record(
                    template, entry.level, total_lines,
                    line.rstrip("\n"), entry.timestamp, entry.service)

                # Issue #102: opt-in comparison evidence, recorded at the
                # same parse/group point so counts reconcile exactly with
                # issue["count"] (same branch, same entries, no re-parse).
                if comparison_evidence is not None:
                    evidence = comparison_evidence.setdefault(template, {
                        "level_counts": {},
                        "examples": {},
                        "examples_truncated": False,
                    })
                    evidence["level_counts"][entry.level] = (
                        evidence["level_counts"].get(entry.level, 0) + 1
                    )
                    examples = evidence["examples"].setdefault(entry.level, [])
                    if len(examples) < 2:
                        text = line.rstrip("\n")
                        if len(text) > 1024:
                            text = text[:1024]
                            evidence["examples_truncated"] = True
                        examples.append({
                            "line_number": total_lines,
                            "text": text,
                            "timestamp": entry.timestamp,
                            "service": entry.service,
                        })
                    else:
                        evidence["examples_truncated"] = True

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

    result = {
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
    result["diagnostic_evidence"] = diagnostic_evidence.build()
    if comparison_evidence is not None:
        result["comparison_evidence"] = comparison_evidence
    return result


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
    per_file_evidence = []

    for log_file in log_files:
        results = analyze_log_file(str(log_file))
        if results.get("diagnostic_evidence") is not None:
            per_file_evidence.append(results["diagnostic_evidence"])

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
            # F04 (#106): cross-file merge also takes the peak level.
            combined["level"] = _peak_level(
                combined["level"], issue_data["level"])
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
        "diagnostic_evidence": _merge_diagnostic_evidence(per_file_evidence),
    }