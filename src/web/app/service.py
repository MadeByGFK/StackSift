"""Core analysis service: takes an uploaded file, runs the StackSift analyzer,
and returns everything the report templates need.

Privacy: recognized patterns are redacted before writing the analysis file.
That file is deleted in a `finally` block during normal execution. Starlette
may already have spooled the raw upload to disk before this service runs.
"""

from __future__ import annotations

import json
import os
import signal
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

# --- Robustness: limits, timeout, binary detection ------------------------

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_UPLOAD_LINES = 50_000
ANALYSIS_TIMEOUT_SECONDS = 25


class AnalysisTimeout(Exception):
    """Raised when analysis exceeds the timeout."""
    pass


def _timeout_handler(signum, frame):
    raise AnalysisTimeout(f"Analysis exceeded {ANALYSIS_TIMEOUT_SECONDS}s")


def _is_binary_content(content: bytes, sample_size: int = 8192) -> bool:
    """Detect binary files via NUL bytes and control character ratio."""
    if b"\x00" in content[:sample_size]:
        return True
    sample = content[:sample_size]
    if not sample:
        return False
    text_chars = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return (len(sample) - text_chars) / len(sample) > 0.3

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
    """Analyze an upload and clean up the analysis file during normal execution."""
    # --- Input validation (robustness) ---
    if len(content) == 0:
        return {
            "error": "empty_file",
            "message": "The uploaded file is empty. Please upload a log file with content.",
            "filename": filename,
        }
    if len(content) > MAX_UPLOAD_BYTES:
        size_mb = len(content) / (1024 * 1024)
        return {
            "error": "file_too_large",
            "message": f"File too large ({size_mb:.1f}MB). Maximum is 10MB. "
                       "For larger files, consider splitting by time range.",
            "filename": filename,
        }
    if _is_binary_content(content):
        return {
            "error": "binary_file",
            "message": "This appears to be a binary file, not a text log. "
                       "StackSift analyzes text logs. If this is a log file, "
                       "ensure it's saved as plain text (UTF-8).",
            "filename": filename,
        }
    text = content.decode("utf-8", errors="replace")
    # Redact recognized patterns before creating the analysis file.
    # This does not cover the framework's earlier raw-upload spool.
    text = redact_secrets(text)
    lines = text.splitlines()
    if len(lines) > MAX_UPLOAD_LINES:
        return {
            "error": "too_many_lines",
            "message": f"Too many lines ({len(lines):,}). Maximum is 50,000 lines. "
                       "For larger files, consider splitting by time range.",
            "filename": filename,
        }

    detected_format = "text"
    adapted = False
    if _looks_like_jsonlines(lines):
        detected_format = "jsonlines"
        adapted = True
        lines = [_jsonline_to_text(line) for line in lines]
        text = "\n".join(lines)

    tmp_path = None
    start = time.perf_counter()
    # SIGALRM covers the ENTIRE pipeline: parsing, ranking, Phase D.
    # (Previous version only covered analyze_log_file, leaving rank_candidates
    # and presentation unprotected against pathological inputs.)
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(ANALYSIS_TIMEOUT_SECONDS)
    try:
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
        ranked, _, truncated, truncated_count = rank_candidates(results["issues"], timeline)
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
    except AnalysisTimeout:
        return {
            "error": "analysis_timeout",
            "message": f"Analysis exceeded {ANALYSIS_TIMEOUT_SECONDS}s timeout. "
                       "The log may contain pathological patterns.",
            "filename": filename,
        }
    finally:
        signal.alarm(0)  # Cancel alarm

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
        # Complexity bound disclosure (never silently present partial results)
        "complexity_truncated": truncated,
        "complexity_notice": (
            f"Analysis covered the {len(ranked)} most frequent of "
            f"{len(ranked) + truncated_count} issue patterns. "
            f"Results may be incomplete due to high diagnostic complexity."
            if truncated else None
        ),
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
        "Uploads may be spooled to disk before redaction. Temporary files are cleaned up during normal processing. Review this report for sensitive data before sharing.",
    ]
    return "\n".join(lines)
