from typing import Optional

from stacksift.models import LogEntry


VALID_LEVELS = {"INFO", "WARN", "ERROR", "CRITICAL"}


def parse_log_line(line: str) -> Optional[LogEntry]:
    parts = line.strip().split(" ", 3)

    if len(parts) < 4:
        return None

    date_part = parts[0]
    time_part = parts[1]
    level = parts[2]
    message = parts[3]

    if level not in VALID_LEVELS:
        return None

    return LogEntry(
        timestamp=f"{date_part} {time_part}",
        level=level,
        message=message,
    )