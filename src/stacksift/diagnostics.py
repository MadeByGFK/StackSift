"""Phase C: Evidence-based diagnostic prioritization.

Replaces severity/rarity-dominated ranking with multi-signal evidence
evaluation. Deterministic, explainable, no LLM calls.

Design principles (from v0.4 architecture decision):
- Escalation is a signal, not a requirement (flat persistent incidents work)
- Explanatory coverage > isolated severity
- Infrastructure is not inherently more causal than application
- Distinguish observed / correlated / hypothesized
- No single signal determines the winner
"""

from collections import Counter


# --- C1: Evidence extraction --------------------------------------------

def _detect_degradation_window(timeline_buckets):
    """Find the degradation window from timeline escalation.

    Returns (start_bucket, end_bucket) or None if no clear escalation.
    A flat timeline returns None — the caller must handle persistent
    incidents without requiring an escalation window.
    """
    if not timeline_buckets or len(timeline_buckets) < 3:
        return None

    counts = [b["warn"] + b["error"] + b["critical"] for b in timeline_buckets]
    peak = max(counts)
    if peak < 10:
        return None

    # Baseline: 25th percentile (same as health badge)
    ordered = sorted(counts)
    baseline = ordered[len(ordered) // 4]
    if baseline < 1:
        baseline = 1

    # Find sustained 2x+ elevation (same threshold as "Increased" badge)
    start = end = None
    run = 0
    for i, c in enumerate(counts):
        if c >= baseline * 2.0 and c >= 10:
            if start is None:
                start = i
            run += 1
            end = i
        else:
            if run >= 2:
                break  # sustained window found
            start = None
            run = 0

    if start is not None and run >= 2:
        return (timeline_buckets[start]["label"],
                timeline_buckets[end]["label"])
    return None


def _resource_pressure_score(issue):
    """0-2: Does telemetry show saturation, exhaustion, contention,
    or resource holding?

    Observed facts from retained numeric values — not hypotheses.
    """
    score = 0
    telemetry = issue.get("telemetry", {})

    # Saturation: active at max, idle at zero
    active = telemetry.get("active", {})
    max_conn = telemetry.get("max_connections", {})
    idle = telemetry.get("idle", {})
    if active and max_conn:
        if active.get("max", 0) >= max_conn.get("min", float("inf")) * 0.95:
            score += 1  # at or near capacity
    if idle and idle.get("min", float("inf")) == 0:
        score += 1  # completely drained

    # Contention: pending waiters
    pending = telemetry.get("pending", {})
    if pending and pending.get("max", 0) > 0:
        score = max(score, 1)  # at least 1 for contention

    # Resource holding: long-held transactions/connections
    # held_ms > 60s suggests a resource not being released
    held = telemetry.get("held_ms", {})
    if held and held.get("max", 0) > 60000:
        score = max(score, 1)  # holding resources is pressure

    return min(score, 2)


def _temporal_alignment_score(issue, degradation_window, timeline_buckets):
    """0-3: Does issue activity align with degradation?

    If no degradation window (flat timeline), scores based on persistence:
    issues active across the full time range get credit for explaining
    persistent conditions.
    """
    buckets = issue.get("telemetry_buckets", {})
    if not buckets:
        # Fall back to first_seen/last_seen
        if issue.get("first_seen") and issue.get("last_seen"):
            return 1  # persistent presence, weak signal
        return 0

    bucket_keys = sorted(buckets.keys())

    if degradation_window:
        start_label, end_label = degradation_window
        # Count buckets within the degradation window
        # Bucket keys are "2026-10-11T12:30", labels are "12:30"
        in_window = sum(
            1 for k in bucket_keys
            if start_label <= k.split("T")[1] <= end_label
        )
        total = len(bucket_keys)
        if total == 0:
            return 0
        ratio = in_window / total
        if ratio >= 0.7:
            return 3  # strongly aligned
        elif ratio >= 0.4:
            return 2  # moderately aligned
        elif ratio > 0:
            return 1  # weakly aligned
        return 0
    else:
        # No escalation window: reward persistence across time
        # (flat-but-persistent incident)
        if len(bucket_keys) >= 5:
            return 2  # sustained throughout observation
        elif len(bucket_keys) >= 2:
            return 1
        return 0


def _cross_service_score(issue):
    """0-2: Does evidence span multiple services?

    Cross-service impact suggests infrastructure/shared dependency
    rather than isolated application bug.
    """
    services = issue.get("services", [])
    n = len(services)
    if n >= 3:
        return 2
    elif n == 2:
        return 1
    return 0


def _correlation_strength_score(issue):
    """0-2: Do correlation samples show real relationships?

    Rewards actual (trace_id, service, db_node) linkages, not just
    co-occurrence of values in sets.
    """
    samples = issue.get("correlation_samples", [])
    if not samples:
        return 0

    # Count distinct meaningful relationships
    relationships = set()
    for s in samples:
        # A relationship is (service, db_node) or (trace_id, db_node)
        key = (
            s.get("service", ""),
            s.get("db_node", ""),
            s.get("pool", ""),
        )
        if any(key):  # at least one meaningful field
            relationships.add(key)

    n = len(relationships)
    if n >= 3:
        return 2
    elif n >= 1:
        return 1
    return 0


def _explanatory_coverage_score(issue, all_issues):
    """0-2: Does this issue's infrastructure overlap with other issues?

    A candidate that shares pool/db_node with many other issues
    plausibly explains multiple symptoms.
    """
    my_pool = set(issue.get("correlation", {}).get("pool", []))
    my_node = set(issue.get("correlation", {}).get("db_node", []))
    if not my_pool and not my_node:
        return 0

    overlapping = 0
    for other_template, other in all_issues.items():
        if other is issue:
            continue
        other_pool = set(other.get("correlation", {}).get("pool", []))
        other_node = set(other.get("correlation", {}).get("db_node", []))
        if (my_pool & other_pool) or (my_node & other_node):
            overlapping += 1

    if overlapping >= 5:
        return 2
    elif overlapping >= 2:
        return 1
    return 0


# --- C2: Explainable ranking --------------------------------------------

# Secondary signals (capped, cannot dominate)
_SEVERITY_WEIGHT = {"CRITICAL": 1.0, "ERROR": 0.8, "WARN": 0.6, "INFO": 0.4}


def _severity_score(level):
    """0-1: Secondary signal. Severity matters but doesn't determine."""
    return _SEVERITY_WEIGHT.get(level, 0.5)


def _diagnostic_specificity_score(template):
    """0-2: Does the message contain specific diagnostic indicators?

    Preserved from the original scoring: keywords like 'idle_in_transaction',
    'watchdog', structured error codes, and field-aware failure signals.
    These indicate the message NAMES the problem, not just that one occurred.
    """
    from stacksift.insights import (
        DIAGNOSTIC_KEYWORDS, _failure_signal_strength, _SPECIFIC_VALUE
    )
    score = 0
    lowered = template.lower()
    if any(kw in lowered for kw in DIAGNOSTIC_KEYWORDS):
        score += 1
    sig = _failure_signal_strength(template)
    if sig >= 2:
        score += 1
    elif sig == 1:
        score += 0.5
    if _SPECIFIC_VALUE.search(template):
        score += 0.5
    return min(score, 2)


def extract_evidence(template, issue, all_issues, degradation_window, timeline_buckets):
    """C1: Derive diagnostic features for one issue.

    Returns dict of signal -> (score, explanation, evidence_tier).
    Tiers: "observed" (direct log evidence), "correlated" (shared
    timing/identifiers), "hypothesized" (plausible but unproven).
    """
    evidence = {}

    # Resource pressure (observed)
    rp = _resource_pressure_score(issue)
    evidence["resource_pressure"] = {
        "score": rp,
        "tier": "observed",
        "detail": f"telemetry shows {rp}/2 pressure signals",
    }

    # Temporal alignment (correlated)
    ta = _temporal_alignment_score(issue, degradation_window, timeline_buckets)
    evidence["temporal_alignment"] = {
        "score": ta,
        "tier": "correlated",
        "detail": (
            f"activity {'aligns with' if degradation_window else 'persists across'} "
            f"observation window"
        ),
    }

    # Cross-service (observed)
    cs = _cross_service_score(issue)
    evidence["cross_service"] = {
        "score": cs,
        "tier": "observed",
        "detail": f"spans {len(issue.get('services', []))} services",
    }

    # Correlation strength (correlated)
    corr = _correlation_strength_score(issue)
    evidence["correlation"] = {
        "score": corr,
        "tier": "correlated",
        "detail": f"{len(issue.get('correlation_samples', []))} relationship samples",
    }

    # Explanatory coverage (hypothesized)
    ec = _explanatory_coverage_score(issue, all_issues)
    evidence["explanatory_coverage"] = {
        "score": ec,
        "tier": "hypothesized",
        "detail": "shares infrastructure with other issues",
    }

    # Severity (secondary, observed)
    sev = _severity_score(issue.get("level", "INFO"))
    evidence["severity"] = {
        "score": sev,
        "tier": "observed",
        "detail": f"{issue.get('level')} severity",
    }

    # Diagnostic specificity (secondary, observed)
    # Preserved from original: does the message NAME the problem?
    spec = _diagnostic_specificity_score(template)
    evidence["specificity"] = {
        "score": spec,
        "tier": "observed",
        "detail": "contains diagnostic keywords or specific error codes",
    }

    return evidence


def rank_candidates(issues, timeline_buckets):
    """C2: Rank issues by evidence-based diagnostic value.

    Returns list of (template, total_score, evidence_dict) sorted
    by score descending. Deterministic, explainable, no LLM.
    """
    degradation_window = _detect_degradation_window(timeline_buckets)

    ranked = []
    for template, issue in issues.items():
        evidence = extract_evidence(
            template, issue, issues, degradation_window, timeline_buckets
        )
        # Weighted sum: primary signals dominate, secondary capped
        # Explanatory coverage and resource pressure are the strongest
        # indicators of diagnostic value. Specificity preserves the
        # original keyword/code signals. Severity is secondary.
        total = (
            evidence["resource_pressure"]["score"] * 2.0 +
            evidence["temporal_alignment"]["score"] * 1.5 +
            evidence["cross_service"]["score"] * 1.5 +
            evidence["correlation"]["score"] * 1.0 +
            evidence["explanatory_coverage"]["score"] * 2.0 +
            evidence["specificity"]["score"] * 1.5 +
            evidence["severity"]["score"] * 0.5
        )
        ranked.append((template, total, evidence))

    # Deterministic tiebreak: template string
    ranked.sort(key=lambda x: (-x[1], x[0]))
    return ranked, degradation_window


def explain_ranking(template, score, evidence):
    """Human-readable explanation of why a candidate ranked where it did.

    Distinguishes observed facts from correlations from hypotheses.
    """
    lines = [f"Score: {score:.1f}"]
    for signal, data in evidence.items():
        if data["score"] > 0:
            lines.append(
                f"  [{data['tier']}] {signal}: {data['score']} — {data['detail']}"
            )
    return "\n".join(lines)
