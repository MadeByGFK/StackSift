import json
import re
from datetime import datetime, timezone
from typing import Optional

from stacksift.models import LogEntry


VALID_LEVELS = {"INFO", "WARN", "ERROR", "CRITICAL", "UNKNOWN"}

# Extra levels folded into the ones we track.
_LEVEL_ALIASES = {
    "DEBUG": "INFO",
    "TRACE": "INFO",
    "FATAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "ERR": "ERROR",
    "WARNING": "WARN",
}

# --- Timestamp handling ------------------------------------------------
# All timestamps normalize to UTC ISO-8601 for chronological sorting.
# Naive timestamps are UTC by contract.

_TS_PATTERNS = [
    # 2026-10-11T12:00:00.000Z, 2026-10-11T14:00:01.728+02:00
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    # 2026-10-11 12:00:00.216, 2026-10-11 12:00:00
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    # 2026-10-11 12:00:00,432 (python logging, comma millis)
    "%Y-%m-%d %H:%M:%S,%f",
]


def _normalize_timestamp(raw: str) -> Optional[str]:
    """Parse a timestamp string, return UTC ISO-8601 or None."""
    raw = raw.strip().replace("Z", "+00:00")
    for pattern in _TS_PATTERNS:
        try:
            dt = datetime.strptime(raw, pattern)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except ValueError:
            continue
    # Fallback: fromisoformat handles most ISO variants.
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except ValueError:
        return None


def _normalize_level(raw: str) -> Optional[str]:
    if not raw:
        return None
    level = raw.upper()
    if level in VALID_LEVELS:
        return level
    return _LEVEL_ALIASES.get(level)


# --- Format patterns ---------------------------------------------------

# Plain with millis: "2026-10-11 12:00:00.216 INFO [database-service] msg"
_PLAIN_MILLIS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?P<level>[A-Z]+) (?:\[(?P<svc>[^\]]+)\] )?(?P<msg>.*)$"
)

# Plain: "2026-10-10 09:15:22 ERROR something broke"
_PLAIN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<level>[A-Z]+) (?P<msg>.*)$"
)

# ISO-8601: "2026-10-10T14:00:00.000Z ERROR [edge-api] msg"
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<level>[A-Z]+) (?:\[(?P<svc>[^\]]+)\] )?(?P<msg>.*)$"
)

# Python logging: "2026-10-11 12:00:00,432 - order_service - INFO - msg"
_PYTHON = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - "
    r"(?P<logger>[\w.]+) - (?P<level>[A-Z]+) - (?P<msg>.*)$"
)

# Java: "2026-10-11 12:00:01.512 INFO com.example.OrderService - msg"
_JAVA = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(?P<level>[A-Z]+) (?P<logger>[\w.]+) - (?P<msg>.*)$"
)

# logfmt: "time=2026-10-11T12:00:00.648Z level=INFO service=x ..."
_LOGFMT_KV = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")

# Service extraction from key=value pairs.
_SVC_KV = re.compile(r"\bservice=([^\s,|]+)")


def _extract_service_kv(text: str) -> Optional[str]:
    m = _SVC_KV.search(text)
    return m.group(1) if m else None


def _canonical_kv_message(text: str) -> str:
    """Extract the structured key=value portion for grouping.

    Text formats put human-readable prose before ' | ', then kv pairs.
    Pairs are sorted alphabetically so the same event groups consistently
    across formats (JSON/logfmt emit alphabetical order).
    """
    if " | " in text:
        text = text.split(" | ", 1)[1]
    text = text.strip()
    # Sort kv pairs for cross-format consistency. Only when the text
    # looks like simple space-separated key=value pairs.
    if text and "=" in text and '"' not in text and " | " not in text:
        parts = text.split()
        if all("=" in p and not p.startswith("=") for p in parts):
            parts.sort(key=lambda p: p.split("=", 1)[0])
            return " ".join(parts)
    return text


def _parse_json(line: str) -> Optional[LogEntry]:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None

    timestamp = _normalize_timestamp(str(obj.get("timestamp", "")))
    level = _normalize_level(str(obj.get("level", ""))) or "UNKNOWN"
    service = obj.get("service")

    # Canonical message from structured fields for cross-format grouping.
    # Alphabetical kv pairs, including service=, matching text format style.
    # Excludes timestamp/level/message which are metadata, not content.
    kv_parts = []
    for key in sorted(obj.keys()):
        if key in ("timestamp", "level", "message"):
            continue
        value = obj[key]
        if isinstance(value, (str, int, float)):
            kv_parts.append(f"{key}={value}")
    message = " ".join(kv_parts)
    if not message.strip():
        message = str(obj.get("message", "")).strip() or "(no message)"

    return LogEntry(timestamp=timestamp or "", level=level,
                    message=message.strip(), service=service)


def _parse_logfmt(line: str) -> Optional[LogEntry]:
    if not line.startswith("time="):
        return None
    fields = {}
    for key, value in _LOGFMT_KV.findall(line):
        fields[key] = value.strip('"')
    if "time" not in fields or "level" not in fields:
        return None

    timestamp = _normalize_timestamp(fields["time"])
    level = _normalize_level(fields["level"]) or "UNKNOWN"
    service = fields.get("service")

    kv_parts = [f"{k}={v}" for k, v in sorted(fields.items())
                if k not in ("time", "level")]
    message = " ".join(kv_parts) or fields.get("message", "(no message)")
    return LogEntry(timestamp=timestamp or "", level=level,
                    message=message, service=service)


def _parse_python(line: str) -> Optional[LogEntry]:
    m = _PYTHON.match(line)
    if not m:
        return None
    timestamp = _normalize_timestamp(m.group("ts"))
    level = _normalize_level(m.group("level"))
    if not level:
        return None
    message = _canonical_kv_message(m.group("msg"))
    service = _extract_service_kv(m.group("msg"))
    return LogEntry(timestamp=timestamp or "", level=level,
                    message=message, service=service)


def _parse_java(line: str) -> Optional[LogEntry]:
    m = _JAVA.match(line)
    if not m:
        return None
    timestamp = _normalize_timestamp(m.group("ts"))
    level = _normalize_level(m.group("level"))
    if not level:
        return None
    message = _canonical_kv_message(m.group("msg"))
    service = _extract_service_kv(m.group("msg"))
    return LogEntry(timestamp=timestamp or "", level=level,
                    message=message, service=service)


def _parse_plain_millis(line: str) -> Optional[LogEntry]:
    m = _PLAIN_MILLIS.match(line)
    if not m:
        return None
    timestamp = _normalize_timestamp(m.group("ts"))
    level = _normalize_level(m.group("level"))
    if not level:
        return None
    message = _canonical_kv_message(m.group("msg"))
    service = m.group("svc") or _extract_service_kv(m.group("msg"))
    return LogEntry(timestamp=timestamp or "", level=level,
                    message=message, service=service)


def _parse_plain(line: str) -> Optional[LogEntry]:
    m = _PLAIN.match(line)
    if not m:
        return None
    level = _normalize_level(m.group("level"))
    if not level:
        return None
    timestamp = _normalize_timestamp(
        f"{m.group('date')} {m.group('time')}")
    message = _canonical_kv_message(m.group("msg"))
    service = _extract_service_kv(m.group("msg"))
    return LogEntry(timestamp=timestamp or "", level=level,
                    message=message, service=service)


def _parse_iso(line: str) -> Optional[LogEntry]:
    m = _ISO.match(line)
    if not m:
        return None
    level = _normalize_level(m.group("level"))
    if not level:
        return None
    timestamp = _normalize_timestamp(m.group("ts"))
    message = _canonical_kv_message(m.group("msg"))
    service = m.group("svc") or _extract_service_kv(m.group("msg"))
    if service:
        message = f"[{service}] {message}"
    return LogEntry(timestamp=timestamp or "", level=level,
                    message=message, service=service)


# ISO timestamp + message, no level: "2026-10-11T12:00:03.240Z Inventory report..."
_ISO_NO_LEVEL = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<msg>.*)$"
)


def _parse_iso_no_level(line: str) -> Optional[LogEntry]:
    """Timestamped note without a severity label → UNKNOWN, keeps timestamp."""
    m = _ISO_NO_LEVEL.match(line)
    if not m:
        return None
    # Don't steal lines that _parse_iso would handle (they have a level).
    # If the message starts with a known level word, let the caller try
    # the stricter parsers first — this is a fallback, so just check
    # the message isn't empty.
    msg = m.group("msg").strip()
    if not msg:
        return None
    timestamp = _normalize_timestamp(m.group("ts"))
    service = _extract_service_kv(msg)
    return LogEntry(timestamp=timestamp or "", level="UNKNOWN",
                    message=msg, service=service)


def _parse_unstructured(line: str) -> LogEntry:
    """Fallback: operational notes without timestamp or severity.

    Never fabricates a level or timestamp — UNKNOWN and empty string.
    """
    service = _extract_service_kv(line)
    return LogEntry(timestamp="", level="UNKNOWN", message=line, service=service)


def parse_log_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    if not line:
        return None

    # JSON first — unambiguous prefix.
    if line.startswith("{"):
        return _parse_json(line)

    # Structured text formats, most specific first.
    for parser in (_parse_logfmt, _parse_python, _parse_java,
                   _parse_plain_millis, _parse_iso, _parse_plain,
                   _parse_iso_no_level):
        result = parser(line)
        if result:
            return result

    # Everything else is an unstructured operational note.
    return _parse_unstructured(line)
