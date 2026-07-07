from dataclasses import dataclass
from typing import Optional


@dataclass
class LogEntry:
    timestamp: str
    level: str
    message: str


VALID_LEVELS = {"INFO", "WARN", "ERROR", "CRITICAL"}


def parse_log_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single log line.

    Expected format:
    YYYY-MM-DD HH:MM:SS LEVEL Message text
    """
    parts = line.strip().split(" ", 3)

    if len(parts) < 4:
        return None

    date_part = parts[0]
    time_part = parts[1]
    level = parts[2]
    message = parts[3]

    if level not in VALID_LEVELS:
        return None

    timestamp = f"{date_part} {time_part}"

    return LogEntry(
        timestamp=timestamp,
        level=level,
        message=message,
    )