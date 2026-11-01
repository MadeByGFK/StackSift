"""Core analysis service: takes an uploaded file, runs the StackSift analyzer,
and returns everything the report templates need.

Privacy: recognized patterns are redacted before writing the analysis file.
That file is deleted in a `finally` block during normal execution. Starlette
may already have spooled the raw upload to disk before this service runs.
"""

from __future__ import annotations

import codecs
import json
import os
import signal
import tempfile
import time

from app.vendor.analyzer import analyze_log_file
from app.redact import redact_secrets, REDACTED
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

# Issue #104: oversize analysis (paid, 3 credits). Free limits above are
# UNCHANGED; these ceilings are inclusive and enforced independently.
MAX_OVERSIZE_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_OVERSIZE_UPLOAD_LINES = 500_000


# Line-break characters with str.splitlines() semantics. "\r\n" is a
# single break and is corrected for below (counted once, not twice).
_LINE_BREAK_CHARS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"


def count_original_lines(content: bytes) -> int:
    """Count ORIGINAL decoded lines, pre-redaction (issue #104, trim T6).

    Redaction must not shrink an over-ceiling upload under the limit, so
    classification counts the decoded input before redact_secrets() runs.
    Uses the same UTF-8-with-replacement decoding and splitlines()
    semantics as analyze_upload().

    Bounded-memory fix (issue #104 follow-up, PR #111 head-3 review):
    the previous implementation decoded the whole upload and
    materialized a full splitlines() list before any ceiling check, so
    a newline-dense upload below the byte ceiling forced a full decode
    plus a full list before rate limiting or auth. This version decodes
    in 1 MiB chunks with an incremental decoder (multi-byte characters
    and CRLF pairs straddling a chunk boundary still count correctly),
    counts breaks per chunk in C, and stops as soon as the oversize
    line ceiling is exceeded. Counts above that ceiling are reported
    as MAX_OVERSIZE_UPLOAD_LINES + 1: classification only needs
    over/under the ceiling, and no caller needs an exact over-ceiling
    count (the route reports the ceiling in its error message).
    """
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    count = 0
    prev_ended_cr = False
    last_char = ""
    saw_text = False
    for start in range(0, len(content), 1024 * 1024):
        chunk = decoder.decode(content[start:start + 1024 * 1024])
        if not chunk:
            continue  # chunk was the first half of a multi-byte char
        saw_text = True
        breaks = sum(chunk.count(ch) for ch in _LINE_BREAK_CHARS)
        breaks -= chunk.count("\r\n")  # CRLF is one break, not two
        if prev_ended_cr and chunk.startswith("\n"):
            breaks -= 1  # CRLF split across chunks: \r already counted
        count += breaks
        if count > MAX_OVERSIZE_UPLOAD_LINES:
            return MAX_OVERSIZE_UPLOAD_LINES + 1
        prev_ended_cr = chunk.endswith("\r")
        last_char = chunk[-1]
    tail = decoder.decode(b"", final=True)
    if tail:
        saw_text = True
        last_char = tail[-1]
    if saw_text and last_char not in _LINE_BREAK_CHARS:
        count += 1  # final partial line after the last break
        if count > MAX_OVERSIZE_UPLOAD_LINES:
            return MAX_OVERSIZE_UPLOAD_LINES + 1
    return count


# --- Issue #116: bounded-memory preprocessing for the oversize path -------
#
# The pre-#116 oversize path decoded the WHOLE upload into one str, then
# materialized a splitlines() list and a redacted copy of that str. For
# valid UTF-8 containing non-BMP characters (e.g. emoji), CPython stores
# the entire decoded string at 4 bytes per character, so a ~92 MB upload
# needed ~368 MB for the decoded str alone — plus the resident byte
# buffer, the splitlines copies, and the redaction copy — and the
# supervised worker died with MemoryError at decode under its 512 MiB
# address-space ceiling before analysis started. The helpers below stream
# the oversize path instead: the upload is decoded incrementally in
# chunks and processed one line at a time, so peak preprocessing memory
# is bounded by the longest single line (times the fixed per-line
# redaction transient), never by the decoded size of the whole upload.
# The standard (free) path is unchanged: at the 10 MB ceiling the legacy
# whole-text flow fits comfortably.

_DECODE_CHUNK_BYTES = 1024 * 1024


def _strip_line_break(line: str) -> str:
    """Remove the single trailing line break splitlines() semantics imply."""
    if line.endswith("\r\n"):
        return line[:-2]
    if line and line[-1] in _LINE_BREAK_CHARS:
        return line[:-1]
    return line


def _iter_decoded_lines(content: bytes):
    """Yield the decoded lines of *content*, one at a time.

    Equivalent to ``content.decode("utf-8", errors="replace").splitlines()``
    (same incremental UTF-8-with-replacement decoding, same line-break
    set, CRLF counted once even when it straddles a chunk boundary), but
    only one line plus one decoded chunk is resident at a time.
    """
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def _decoded_chunks():
        for start in range(0, len(content), _DECODE_CHUNK_BYTES):
            yield decoder.decode(content[start:start + _DECODE_CHUNK_BYTES])
        yield decoder.decode(b"", final=True)

    buf = ""
    for text_chunk in _decoded_chunks():
        if not text_chunk:
            continue  # chunk was the first half of a multi-byte character
        parts = (buf + text_chunk).splitlines(True)
        if not parts:
            buf = ""
            continue
        # Every part but the last ends with a line break, so it is a
        # complete line. The last part is held: it may be a partial line,
        # or end in "\r" whose "\n" half arrives in the next chunk.
        for part in parts[:-1]:
            yield _strip_line_break(part)
        buf = parts[-1]
    if buf:
        yield _strip_line_break(buf)


def _oversize_preflight(content: bytes) -> tuple[int, bool]:
    """Streaming pass 1 for the oversize path.

    Returns (original_line_count, is_jsonlines): the ORIGINAL decoded
    line count, pre-redaction (T6 — redaction must not shrink an
    over-ceiling upload under the limit), and the JSON-lines verdict,
    computed with the same sampling rule as _looks_like_jsonlines over
    the redacted first _SAMPLE_LINES lines, without retaining them.
    """
    count = 0
    checked = 0
    hits = 0
    for index, line in enumerate(_iter_decoded_lines(content)):
        count += 1
        if index < _SAMPLE_LINES:
            sample = redact_secrets(line).strip()
            if not sample:
                continue
            checked += 1
            try:
                if isinstance(json.loads(sample), dict):
                    hits += 1
            except (json.JSONDecodeError, ValueError):
                pass
    return count, (checked > 0 and hits / checked >= 0.5)


_PEM_BEGIN_MARKER = "-----BEGIN "
_PEM_END_MARKER = "PRIVATE KEY-----"


def _write_streamed_analysis_file(content: bytes, adapt_jsonlines: bool, out) -> None:
    """Streaming pass 2 for the oversize path: write the redacted (and,
    for JSON-lines input, adapted) analysis file one line at a time.

    Redaction is per line, matching redact_secrets() semantics for every
    pattern that lives within a line. The one multi-line pattern — a PEM
    private-key block — is handled statefully: the begin line is emitted
    with everything from the marker onward replaced by REDACTED, and the
    following lines are dropped until the end marker line, so key
    material never reaches the analysis file (the whole-text flow
    collapses the block to a single REDACTED token in place; the
    streamed flow keeps the surrounding lines separate — the secret
    itself is removed identically).
    """
    in_pem_block = False
    for line in _iter_decoded_lines(content):
        if in_pem_block:
            if _PEM_END_MARKER in line and "-----END " in line:
                in_pem_block = False
            continue
        begin = line.find(_PEM_BEGIN_MARKER)
        if (begin != -1 and _PEM_END_MARKER in line
                and "-----END " not in line[begin:]):
            out.write(redact_secrets(line[:begin]) + REDACTED + "\n")
            in_pem_block = True
            continue
        redacted = redact_secrets(line)
        if adapt_jsonlines:
            redacted = _jsonline_to_text(redacted)
        out.write(redacted + "\n")


def classify_upload_size(nbytes: int, nlines: int) -> str:
    """Classify an upload by the free and oversize ceilings (inclusive).

    Returns "standard" (both free limits met), "oversize" (a free limit is
    exceeded but both oversize ceilings are met), or "unsupported" (an
    oversize ceiling is exceeded). Bytes and lines are enforced
    independently: a small-byte file with 50,001 lines is oversize, as is
    a few-line file over 10 MiB. Input is never truncated to qualify.
    """
    if nbytes <= MAX_UPLOAD_BYTES and nlines <= MAX_UPLOAD_LINES:
        return "standard"
    if nbytes <= MAX_OVERSIZE_UPLOAD_BYTES and nlines <= MAX_OVERSIZE_UPLOAD_LINES:
        return "oversize"
    return "unsupported"


class AnalysisTimeout(Exception):
    """Raised when analysis exceeds the timeout."""
    pass


def _timeout_handler(signum, frame):
    raise AnalysisTimeout(f"Analysis exceeded {ANALYSIS_TIMEOUT_SECONDS}s")


def _is_binary_content(content: bytes, sample_size: int = 8192) -> bool:
    """Detect binary files via magic bytes, NUL bytes, and control char ratio."""
    if not content:
        return False
    # Magic-byte signatures for common binary formats (P1-A1).
    # Catches files with mostly-ASCII headers (PNG is ~17% non-text).
    # Short signatures (MZ) require additional binary evidence to avoid
    # false positives on text like "MZ service started".
    _BINARY_MAGIC = (
        b"\x89PNG\r\n\x1a\n",  # PNG

        b"PK\x03\x04",          # ZIP (also JAR, DOCX, XLSX)
        b"PK\x05\x06",          # ZIP (empty archive)
        b"PK\x07\x08",          # ZIP (spanned)
        b"GIF87a", b"GIF89a",   # GIF
        b"\xff\xd8\xff",        # JPEG
        b"\x1f\x8b",            # GZIP
        b"\x7fELF",             # ELF executable
        b"\xca\xfe\xba\xbe",    # Java class / Mach-O
    )
    for magic in _BINARY_MAGIC:
        if content.startswith(magic):
            return True
    # PDF: require %PDF- followed by a digit (e.g., %PDF-1.4).
    # Plain text like "%PDF-export completed" must not be rejected.
    if content.startswith(b"%PDF-") and len(content) > 5 and content[5:6].isdigit():
        return True
    # MZ executables: require NUL bytes or high non-text ratio in header
    # to avoid false positives on text starting with "MZ".
    if content.startswith(b"MZ"):
        header = content[:64]
        if b"\x00" in header:
            return True
        non_text = sum(1 for b in header if not (32 <= b <= 126 or b in (9, 10, 13)))
        if len(header) > 0 and non_text / len(header) > 0.3:
            return True
        # Text starting with "MZ" falls through to normal checks below
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


def analyze_upload(filename: str, content: bytes, *, allow_oversize: bool = False,
                   use_alarm: bool = True, original_byte_count: int | None = None,
                   collect_comparison_evidence: bool = False) -> dict:
    """Analyze an upload and clean up the analysis file during normal execution.

    allow_oversize=True (issue #104) raises the ceilings to 100 MB /
    500,000 lines and counts ORIGINAL decoded lines pre-redaction (T6) for
    the line ceiling. use_alarm=False is for the supervised oversize worker,
    whose parent process enforces the deadline instead (T5: SIGALRM is never
    moved into a thread; the standard path keeps its 25-second SIGALRM).

    Issue #116: with allow_oversize=True the preprocessing (line counting,
    JSON-lines sampling, redaction, analysis-file writing) streams line
    by line via _iter_decoded_lines, so a supported upload whose decoded
    form expands (non-BMP characters store at 4 bytes/char) cannot exceed
    the supervised worker's memory ceiling merely by being decoded.

    original_byte_count (issue #104 follow-up, PR #111 finding 6): when the
    supervised worker analyzes REDACTED bytes for a confirmed oversize run,
    the byte ceiling must be checked against the SERVER-measured original
    byte count (validated at confirmation from consent metadata), not
    against len(content) of the transformed bytes — redaction can expand
    a near-ceiling secret-dense file past 100 MB (a short labeled value
    grows by 9 bytes per occurrence), which previously failed a run the
    product had already quoted. When None (every non-worker path), the
    ceiling is checked against len(content) as before. The line ceiling
    already behaves this way (pre-redaction counting, T6).
    """
    # --- Input validation (robustness) ---
    byte_limit = MAX_OVERSIZE_UPLOAD_BYTES if allow_oversize else MAX_UPLOAD_BYTES
    line_limit = MAX_OVERSIZE_UPLOAD_LINES if allow_oversize else MAX_UPLOAD_LINES
    if len(content) == 0:
        return {
            "error": "empty_file",
            "message": "The uploaded file is empty. Please upload a log file with content.",
            "filename": filename,
        }
    measured_bytes = original_byte_count if original_byte_count is not None else len(content)
    if measured_bytes > byte_limit:
        size_mb = measured_bytes / (1024 * 1024)
        if allow_oversize:
            return {
                "error": "file_too_large",
                "message": f"File too large ({size_mb:.1f}MB). Maximum is 100MB. "
                           "For larger files, consider splitting by time range.",
                "filename": filename,
            }
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
    # Issue #116: the oversize path never materializes the whole decoded
    # text (see _iter_decoded_lines). It counts original lines and samples
    # the format in one streaming pass here, and writes the redacted
    # analysis file in a second streaming pass below. The standard path
    # keeps the legacy whole-text flow exactly.
    streaming = allow_oversize
    text = None
    if streaming:
        # T6: count ORIGINAL decoded lines pre-redaction. Redaction must
        # not shrink an over-ceiling upload under the limit.
        original_line_count, is_jsonlines = _oversize_preflight(content)
        if original_line_count > line_limit:
            return {
                "error": "too_many_lines",
                "message": f"Too many lines ({original_line_count:,}). Maximum is 500,000 lines. "
                           "For larger files, consider splitting by time range.",
                "filename": filename,
            }
        detected_format = "jsonlines" if is_jsonlines else "text"
        adapted = is_jsonlines
    else:
        text = content.decode("utf-8", errors="replace")
        # T6: count ORIGINAL decoded lines pre-redaction. Redaction must
        # not shrink an over-ceiling upload under the limit.
        original_line_count = len(text.splitlines())
        # Redact recognized patterns before creating the analysis file.
        # This does not cover the framework's earlier raw-upload spool.
        text = redact_secrets(text)
        lines = text.splitlines()
        checked_lines = original_line_count if allow_oversize else len(lines)
        if checked_lines > line_limit:
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
    # T5: the oversize worker runs with use_alarm=False; its parent process
    # enforces the deadline, so no SIGALRM is armed here.
    if use_alarm:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(ANALYSIS_TIMEOUT_SECONDS)
    try:
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".log", delete=False, encoding="utf-8"
            ) as tmp:
                tmp_path = tmp.name
                if streaming:
                    _write_streamed_analysis_file(content, adapted, tmp)
                else:
                    tmp.write(text)

            # Issue #102: opt-in comparison evidence, default OFF so the
            # single-file result shape is unchanged for every other caller.
            results = analyze_log_file(
                tmp_path, collect_comparison_evidence=collect_comparison_evidence)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        elapsed = time.perf_counter() - start

        # P1-D2: Count events and timestamped events for health messaging.
        _events = results.get("events", [])
        _timestamped = sum(1 for e in _events if e[0])
        health_label, health_color = determine_health(
            results["level_counts"],
            [b["warn"] + b["error"] + b["critical"]
             for b in build_timeline(_events)],
            events_total=len(_events),
            timestamped_total=_timestamped,
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
        if use_alarm:
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
