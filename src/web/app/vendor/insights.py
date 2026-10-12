SEVERITY_ORDER = {
    "CRITICAL": 0,
    "ERROR": 1,
    "WARN": 2,
    "INFO": 3,
}

SEVERITY_WEIGHT = {
    "CRITICAL": 4,
    "ERROR": 3,
    "WARN": 2,
    "INFO": 1,
}

# Substrings that suggest a message explains *why* something broke,
# not just *that* it broke. Used to boost diagnostic ranking.
DIAGNOSTIC_KEYWORDS = [
    "idle_in_transaction",
    "leak",
    "watchdog",
    "saturated",
    "deadlock",
    "unreleased",
    "exhausted",
    "corrupt",
    "out_of_memory",
    "outofmemory",
    "circuit_breaker",
    "starvation",
]

# Field-aware failure signals.
# A bare `=false` is not diagnostic by itself — `retryable=false` just means
# "don't retry", while `verification=X509_V_ERR_CERT_HAS_EXPIRED` names the
# actual problem. So we weigh the FIELD, not just the value:
# - high-value fields (verification, reason, error, ...) carry diagnosis
# - low-value fields (retryable, dropped, counters) are metadata
# - specific values (X509_V_ERR_CERT_HAS_EXPIRED) beat generic ones (false)
import re as _re

_FAILURE_WORDS = {
    "false", "failed", "failure", "expired", "invalid", "denied",
    "refused", "timeout", "timed_out", "unreachable", "corrupt",
    "exhausted", "rejected",
}
_HIGH_VALUE_FIELDS = {
    "verification", "reason", "error", "exception", "cause",
    "failure", "result", "status_detail", "release_observed",
    "cert_status", "auth_result",
}
_LOW_VALUE_FIELDS = {
    "retryable", "dropped", "queue_items", "delay_ms", "duration_ms",
    "attempt", "max_attempts",
}
# e.g. X509_V_ERR_CERT_HAS_EXPIRED — long, structured, specific.
_SPECIFIC_VALUE = _re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}\b")
_KV_PAIR = _re.compile(r"\b(\w+)=([A-Za-z0-9_\-\.]+)")


def _failure_signal_strength(message: str) -> int:
    """0 = none, 1 = generic, 2 = strong. Field-aware, not just value-aware."""
    best = 0
    for match in _KV_PAIR.finditer(message):
        key, value = match.group(1).lower(), match.group(2)
        if key in _LOW_VALUE_FIELDS:
            continue
        lowered_value = value.lower()
        has_failure_word = any(fw in lowered_value for fw in _FAILURE_WORDS)
        is_specific = bool(_SPECIFIC_VALUE.search(value))
        if key in _HIGH_VALUE_FIELDS and (has_failure_word or is_specific):
            return 2
        if has_failure_word or is_specific:
            best = max(best, 1)
    return best


def diagnostic_score(level: str, message: str, count: int) -> float:
    """Score how diagnostically valuable an issue is.

    Frequency alone is a poor proxy for importance: a single
    `idle_in_transaction` watchdog event can explain hundreds of
    repetitive pool-wait warnings. Severity and diagnostic keywords
    drive the score; rarity is only a small tiebreaker nudge so it
    can never flip a severity tier on its own.
    """
    weight = SEVERITY_WEIGHT.get(level, 1)
    lowered = message.lower()
    keyword_hits = sum(1 for kw in DIAGNOSTIC_KEYWORDS if kw in lowered)
    # Field-aware failure signal (0-2): strong signals like
    # verification=X509_V_ERR_CERT_HAS_EXPIRED count double; generic
    # metadata like retryable=false counts for nothing.
    keyword_hits += _failure_signal_strength(message)
    # Specificity: structured error codes (X509_V_ERR_..., SQLSTATE_...)
    # are more diagnostic than prose values. Capped so it breaks ties
    # between strong signals without dominating.
    if _SPECIFIC_VALUE.search(message):
        keyword_hits += 1
    rarity_nudge = min(0.5, 2.0 / max(count, 1))
    return weight * (1 + keyword_hits) + rarity_nudge


def most_diagnostic_issue(issues: dict):
    """The issue most likely to explain the incident (not just the loudest)."""
    if not issues:
        return None
    return max(
        issues.items(),
        key=lambda item: diagnostic_score(
            item[1]["level"], item[0], item[1]["count"]
        ),
    )


def diagnostic_reasons(level: str, message: str, count: int) -> list[str]:
    """Human-readable reasons why an issue ranked highly. Keeps the
    scoring explainable: each reason maps to a scoring input."""
    reasons = []
    if level in ("CRITICAL", "ERROR"):
        reasons.append(f"{level.title()} severity")
    lowered = message.lower()
    hits = [kw for kw in DIAGNOSTIC_KEYWORDS if kw in lowered]
    if hits:
        reasons.append(f"Diagnostic keywords: {', '.join(hits)}")
    strength = _failure_signal_strength(message)
    if strength >= 2:
        # Surface the actual high-value finding, not just "failure".
        specifics = []
        for match in _KV_PAIR.finditer(message):
            key, value = match.group(1), match.group(2)
            if key.lower() in _HIGH_VALUE_FIELDS and (
                any(fw in value.lower() for fw in _FAILURE_WORDS)
                or _SPECIFIC_VALUE.search(value)
            ):
                specifics.append(f"{key}={value}")
        if specifics:
            reasons.append(f"Failure signals: {', '.join(specifics)}")
        else:
            reasons.append("Strong failure signal")
    elif strength == 1:
        reasons.append("Failure-indicating values present")
    if count <= 3:
        reasons.append(
            f"Rare event ({count} occurrence{'s' if count != 1 else ''})"
        )
    elif count >= 100:
        reasons.append(f"High frequency ({count} occurrences)")
    return reasons


# --- Incident timeline ----------------------------------------------------

from datetime import datetime, timedelta


def _parse_timestamp(ts: str):
    """Parse the timestamp formats our parser emits."""
    ts = ts.strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    # fromisoformat as a last resort (handles offsets like +00:00)
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def build_timeline(events, bucket_minutes=5):
    """Bucket (timestamp, level) events into fixed windows.

    Returns a list of dicts: {start, label, warn, error, critical, total}.
    Empty input returns [].
    """
    parsed = []
    for ts_str, level in events:
        dt = _parse_timestamp(ts_str) if isinstance(ts_str, str) else ts_str
        if dt is None:
            continue
        # drop tzinfo for bucketing (all events share a zone in practice)
        parsed.append((dt.replace(tzinfo=None), level))
    if not parsed:
        return []

    parsed.sort()
    start = parsed[0][0].replace(
        minute=(parsed[0][0].minute // bucket_minutes) * bucket_minutes,
        second=0, microsecond=0,
    )
    end = parsed[-1][0]
    buckets = []
    cursor = start
    while cursor <= end:
        buckets.append({
            "start": cursor,
            "label": cursor.strftime("%H:%M"),
            "warn": 0, "error": 0, "critical": 0, "total": 0,
        })
        cursor += timedelta(minutes=bucket_minutes)

    for dt, level in parsed:
        idx = int((dt - start).total_seconds() // (bucket_minutes * 60))
        if 0 <= idx < len(buckets):
            b = buckets[idx]
            if level == "WARN":
                b["warn"] += 1
            elif level == "ERROR":
                b["error"] += 1
            elif level == "CRITICAL":
                b["critical"] += 1
            b["total"] += 1

    _label_phases(buckets)
    return buckets


def _label_phases(buckets):
    """Tag each bucket with a phase: baseline, escalating, peak, recovering."""
    counts = [b["warn"] + b["error"] + b["critical"] for b in buckets]
    peak = max(counts) if counts else 0
    if peak == 0:
        for b in buckets:
            b["phase"] = "baseline"
        return

    threshold = max(1, peak * 0.15)
    # incident window: first to last bucket above threshold
    active = [i for i, c in enumerate(counts) if c >= threshold]
    first, last = active[0], active[-1]
    peak_idx = counts.index(peak)

    for i, b in enumerate(buckets):
        if i < first or i > last:
            b["phase"] = "baseline"
        elif i < peak_idx:
            b["phase"] = "escalating"
        elif i == peak_idx:
            b["phase"] = "peak"
        else:
            # Declining error counts don't prove recovery — the service
            # could be down, not healed. Label honestly.
            b["phase"] = "declining"


def determine_health(
    level_counts: dict, bucket_totals: list[int] | None = None
) -> tuple[str, str]:
    """Classify the log's activity pattern from timeline escalation.

    Labels are observational, not diagnostic: they describe what the
    activity pattern shows, not whether the application is healthy.
    A flat timeline with warnings is "No Escalation Detected", not
    "Healthy" — stability is not proof of health.

    Escalation is measured as sustained elevation relative to baseline
    (25th percentile of bucket counts, robust to spikes). A single
    isolated spike does not qualify; elevation must persist across
    consecutive buckets. Minimum event counts guard against noisy
    ratios in sparse data (1 -> 7 is 7x but meaningless).
    """
    critical = level_counts.get("CRITICAL", 0)
    if critical > 0:
        return ("Critical", "red")

    if not bucket_totals:
        return ("Health Undetermined", "gray")

    peak = max(bucket_totals)
    if peak == 0:
        return ("No Significant Issues Detected", "green")

    non_empty = [b for b in bucket_totals if b > 0]
    if len(non_empty) < 3:
        return ("Health Undetermined", "gray")

    # Baseline: 25th percentile — the lower-normal activity level.
    # Robust to incident spikes pulling the median up.
    ordered = sorted(bucket_totals)
    baseline = ordered[len(ordered) // 4]
    if baseline < 1:
        baseline = 1  # avoid division by zero; conservative

    # Too sparse for meaningful ratios.
    if peak < 10:
        return ("Health Undetermined", "gray")

    def sustained(ratio: float, consecutive: int = 2) -> bool:
        """True if >= ratio x baseline persists across consecutive buckets,
        each with enough events to be meaningful."""
        run = 0
        for count in bucket_totals:
            if count >= baseline * ratio and count >= 10:
                run += 1
                if run >= consecutive:
                    return True
            else:
                run = 0
        return False

    if sustained(3.0):
        return ("Elevated Incident Activity", "red")
    if sustained(2.0):
        return ("Increased Error Activity", "yellow")
    return ("No Escalation Detected", "green")


def most_frequent_issue(issues: dict):
    if not issues:
        return None

    return max(
        issues.items(),
        key=lambda item: item[1]["count"]
    )

def sort_issues_by_severity(issues: dict) -> list:
    """
    Sort issues by severity first, then by occurrence count.
    """

    return sorted(
        issues.items(),
        key=lambda item: (
            SEVERITY_ORDER.get(item[1]["level"], 99),
            -item[1]["count"],
        ),
    )