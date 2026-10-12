"""Core analysis service: takes an uploaded file, runs the StackSift analyzer,
and returns everything the report templates need.

Privacy: the upload is written to a temp file, analyzed, and deleted in a
`finally` block. File contents are never logged, stored, or persisted.
"""

from __future__ import annotations

import json
import os
import tempfile
import time

from app.vendor.analyzer import analyze_log_file
from app.redact import redact_secrets
from app.vendor.insights import (
    build_timeline,
    determine_health,
    diagnostic_reasons,
    most_frequent_issue,
    sort_issues_by_severity,
)
from app.vendor.diagnostics import (
    rank_candidates,
    explain_ranking,
    build_incident_section,
    build_notable_events,
    _detect_degradation_window,
)

# JSON-lines field names we recognize (common variants).
_TS_FIELDS = ("timestamp", "time", "@timestamp", "datetime", "ts")
_LEVEL_FIELDS = ("level", "severity", "loglevel", "log_level")
_MSG_FIELDS = ("message", "msg", "text", "event")

_LEVEL_MAP = {
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "fatal": "CRITICAL",
    "error": "ERROR",
    "err": "ERROR",
    "warning": "WARN",
    "warn": "WARN",
    "info": "INFO",
    "information": "INFO",
    # The analyzer only tracks four levels; DEBUG/TRACE are folded into INFO
    # and disclosed on the report page.
    "debug": "INFO",
    "trace": "INFO",
}

_SAMPLE_LINES = 200


def _looks_like_jsonlines(lines: list[str]) -> bool:
    """Heuristic: if most of the sampled lines parse as JSON objects, treat
    the file as JSON-lines."""
    checked = 0
    hits = 0
    for line in lines[:_SAMPLE_LINES]:
        line = line.strip()
        if not line:
            continue
        checked += 1
        try:
            if isinstance(json.loads(line), dict):
                hits += 1
        except (json.JSONDecodeError, ValueError):
            pass
    return checked > 0 and hits / checked >= 0.5


def _pick(obj: dict, fields: tuple[str, ...]) -> str:
    for field in fields:
        value = obj.get(field)
        if value is not None and value != "":
            return str(value)
    return ""


def _jsonline_to_text(line: str) -> str:
    """Convert one JSON log line into the plain-text format the analyzer
    understands: `<date> <time> <LEVEL> <message>`."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return line
    if not isinstance(obj, dict):
        return line

    timestamp = _pick(obj, _TS_FIELDS).replace("T", " ").replace("Z", "").strip()
    if " " in timestamp:
        date_part, time_part = timestamp.split(" ", 1)
    elif timestamp:
        date_part, time_part = timestamp, "00:00:00"
    else:
        date_part, time_part = "-", "-"

    raw_level = _pick(obj, _LEVEL_FIELDS).lower()
    level = _LEVEL_MAP.get(raw_level, "INFO")

    message = _pick(obj, _MSG_FIELDS).replace("\n", " ").strip() or "(no message)"
    return f"{date_part} {time_part} {level} {message}"


def analyze_upload(filename: str, content: bytes) -> dict:
    """Analyze an uploaded log file. Returns report data; never retains the file."""
    text = content.decode("utf-8", errors="replace")
    # Redact secrets first: they never reach the analyzer, the report, or disk.
    text = redact_secrets(text)
    lines = text.splitlines()

    detected_format = "text"
    adapted = False
    if _looks_like_jsonlines(lines):
        detected_format = "jsonlines"
        adapted = True
        lines = [_jsonline_to_text(line) for line in lines]
        text = "\n".join(lines)

    tmp_path = None
    start = time.perf_counter()
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(text)
            tmp_path = tmp.name

        results = analyze_log_file(tmp_path)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
    elapsed = time.perf_counter() - start

    health_label, health_color = determine_health(
        results["level_counts"],
        [b["warn"] + b["error"] + b["critical"]
         for b in build_timeline(results.get("events", []))],
    )

    # Phase C: evidence-based diagnostic ranking
    timeline = build_timeline(results.get("events", []))
    ranked, _ = rank_candidates(results["issues"], timeline)
    diagnostic = None
    diagnostic_explanation = None
    if ranked:
        top_template, top_score, top_evidence = ranked[0]
        top_issue = results["issues"][top_template]
        diagnostic = (top_template, top_issue)
        diagnostic_explanation = explain_ranking(
            top_template, top_score, top_evidence
        )

    # Phase D: incident section and notable events
    # (diagnostic_issue contract preserved for backward compatibility)
    degradation_window = _detect_degradation_window(timeline)
    incident_section = build_incident_section(
        ranked, results["issues"], degradation_window, timeline
    )
    # Collect templates shown in incident section to exclude from notable
    incident_templates = set()
    if incident_section["type"] != "none" and ranked:
        incident_templates.add(ranked[0][0])
        se = incident_section.get("supporting_evidence", {})
        for key in ("observed", "correlated", "hypothesized"):
            for item in se.get(key, []):
                incident_templates.add(item[0])
    notable_events = build_notable_events(
        ranked, results["issues"], incident_templates
    )

    return {
        "filename": filename,
        "detected_format": detected_format,
        "adapted": adapted,
        "results": results,
        "health": {"label": health_label, "color": health_color},
        "sorted_issues": sort_issues_by_severity(results["issues"]),
        "top_issue": most_frequent_issue(results["issues"]),
        "diagnostic_issue": diagnostic,
        "diagnostic_explanation": diagnostic_explanation,
        "incident_section": incident_section,
        "notable_events": notable_events,
        "timeline": timeline,
        "first_seen": results.get("first_seen"),
        "last_seen": results.get("last_seen"),
        "elapsed": elapsed,
    }


def render_text_report(data: dict) -> str:
    """Plain-text version of the report, for download."""
    r = data["results"]
    lines = [
        "StackSift Summary",
        "",
        f"File: {data['filename']}",
        f"Detected format: {data['detected_format']}",
        f"Health: {data['health']['label']}",
        "",
        f"Total lines: {r['total_lines']}",
        f"Parsed lines: {r['parsed_lines']}",
        f"Malformed lines: {r['malformed_lines']}",
        "",
        "Log Levels:",
    ]
    for level in ("CRITICAL", "ERROR", "WARN", "INFO"):
        count = r["level_counts"].get(level, 0)
        lines.append(f"- {level}: {count}")
    lines += ["", "Issues (sorted by severity, then frequency):"]
    for issue, issue_data in data["sorted_issues"]:
        lines.append(f"- [{issue_data['level']}] {issue} (x{issue_data['count']})")
    lines += [
        "",
        "Generated by StackSift — https://stacksift.goodfolkdigital.com",
        "Your file was analyzed in memory and deleted immediately afterwards.",
    ]
    return "\n".join(lines)
