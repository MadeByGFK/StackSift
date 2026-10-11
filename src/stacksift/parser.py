import re
from typing import Optional

from stacksift.models import LogEntry


VALID_LEVELS = {"INFO", "WARN", "ERROR", "CRITICAL"}

# Extra levels folded into the four we track (mirrors service._LEVEL_MAP).
_LEVEL_ALIASES = {
    "DEBUG": "INFO",
    "TRACE": "INFO",
    "FATAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "ERR": "ERROR",
    "WARNING": "WARN",
}

# Format A: "2026-10-10 09:15:22 ERROR something broke"
_PLAIN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<level>[A-Z]+) (?P<msg>.*)$"
)

# Format B: "2026-10-10T14:00:00.000Z ERROR [edge-api] http_request ..."
# ISO-8601 timestamp, optional [service] tag.
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<level>[A-Z]+) (?:\[(?P<svc>[^\]]+)\] )?(?P<msg>.*)$"
)


def _normalize_level(raw: str) -> Optional[str]:
    level = raw.upper()
    if level in VALID_LEVELS:
        return level
    return _LEVEL_ALIASES.get(level)


def parse_log_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    if not line:
        return None

    match = _PLAIN.match(line) or _ISO.match(line)
    if not match:
        return None

    level = _normalize_level(match.group("level"))
    if not level:
        return None

    parts = match.groupdict()
    timestamp = parts.get("ts") or f"{parts['date']} {parts['time']}"
    message = parts["msg"].strip()
    service = parts.get("svc")
    if service:
        message = f"[{service}] {message}"

    if not message:
        return None

    return LogEntry(timestamp=timestamp, level=level, message=message,
                    service=service)
