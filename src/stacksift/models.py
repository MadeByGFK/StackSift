from dataclasses import dataclass


@dataclass
class LogEntry:
    timestamp: str
    level: str
    message: str