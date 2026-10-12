from dataclasses import dataclass
from typing import Optional


@dataclass
class LogEntry:
    timestamp: str
    level: str
    message: str
    service: Optional[str] = None