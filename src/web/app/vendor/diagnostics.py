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
    from app.vendor.insights import (
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

    # Timing availability (for Phase D section classification)
    # Not a score — records whether temporal reasoning is possible.
    evidence["_has_timing"] = _has_usable_timing(issue)

    return evidence


# Complexity bound: maximum issues to rank.
# Prevents O(N^2) blowup in _explanatory_coverage_score when high-cardinality
# IDs defeat template normalization. Issues are pre-sorted by frequency so
# the most common patterns are always ranked.
MAX_RANK_CANDIDATES = 1000


def rank_candidates(issues, timeline_buckets, max_candidates=MAX_RANK_CANDIDATES):
    """C2: Rank issues by evidence-based diagnostic value.

    Returns (ranked, degradation_window, truncated) where ranked is a list
    of (template, total_score, evidence_dict) sorted by score descending.
    Deterministic, explainable, no LLM.

    If len(issues) exceeds max_candidates, only the most frequent issues
    are ranked and truncated=True. Callers must surface truncation; never
    silently present partial results as comprehensive.
    """
    degradation_window = _detect_degradation_window(timeline_buckets)

    # Bound complexity before O(N^2) evidence extraction
    truncated = False
    truncated_count = 0
    if len(issues) > max_candidates:
        truncated = True
        truncated_count = len(issues) - max_candidates
        # Preselect candidates by diagnostic importance, not just frequency.
        # A rare CRITICAL issue with specific error codes must not be dropped
        # in favor of thousands of routine errors.
        # Order: severity (CRITICAL first), specificity (named problems first),
        # then frequency, then template for determinism.
        # This is candidate SELECTION, not scoring — the evidence-based ranking
        # below is unchanged.
        _SEV_ORDER = {"CRITICAL": 0, "ERROR": 1, "WARN": 2, "INFO": 3}
        def _preselect_key(kv):
            template, issue = kv
            sev = _SEV_ORDER.get(issue.get("level", "INFO"), 4)
            # Specificity: does the template NAME the problem?
            # (Uses the same signal as the ranking's specificity score,
            # but computed here for preselection only.)
            spec = _diagnostic_specificity_score(template)
            count = issue.get("count", 0)
            return (sev, -spec, -count, template)
        sorted_by_importance = sorted(issues.items(), key=_preselect_key)
        issues = dict(sorted_by_importance[:max_candidates])

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
    return ranked, degradation_window, truncated, truncated_count


def explain_ranking(template, score, evidence):
    """Human-readable explanation of why a candidate ranked where it did.

    Returns a list of strings (one per evidence point) for template joining.
    Uses plain language, not raw scoring internals.
    """
    points = []
    for signal, data in evidence.items():
        if signal.startswith("_"):
            continue  # skip internal metadata
        if data["score"] <= 0:
            continue
        tier = data["tier"]
        detail = data["detail"]
        # Human-readable, tier-aware phrasing
        if tier == "observed":
            points.append(detail)
        elif tier == "correlated":
            points.append(f"Correlated: {detail}")
        elif tier == "hypothesized":
            points.append(f"Possible link: {detail}")
    return points


# --- Phase D: Presentation layer ----------------------------------------

def _has_usable_timing(issue):
    """Does this issue have timestamps we can reason about?"""
    buckets = issue.get("telemetry_buckets", {})
    return bool(buckets) and bool(issue.get("first_seen"))


def _is_corroborated(evidence):
    """At least one corroborating signal beyond the issue itself."""
    return (
        evidence["explanatory_coverage"]["score"] >= 1 or
        evidence["resource_pressure"]["score"] >= 1 or
        evidence["cross_service"]["score"] >= 1 or
        evidence["correlation"]["score"] >= 1
    )


def _is_strongly_corroborated(evidence):
    """Stronger bar for the missing-timing path.

    Missing timing cannot count as positive evidence, so we require
    more independent corroboration.
    """
    signals = sum([
        evidence["explanatory_coverage"]["score"] >= 1,
        evidence["resource_pressure"]["score"] >= 1,
        evidence["cross_service"]["score"] >= 1,
        evidence["correlation"]["score"] >= 1,
    ])
    return signals >= 3


def classify_incident_section(ranked, degradation_window):
    """Phase D: Determine if top candidate qualifies for Incident investigation.

    Returns (section_type, candidate_idx) where section_type is:
    - "active_incident": degradation window + qualified candidate
    - "persistent_failure": no window but sustained corroborated activity
    - "none": no candidate qualifies

    Adjustment A: temporal_alignment >= 2 is not a universal gate.
    When timing is unavailable, an alternative path requires stronger
    independent corroboration.
    """
    if not ranked:
        return ("none", None)

    template, score, evidence = ranked[0]
    # We need the issue dict; ranked doesn't carry it, so we work with
    # what we have and require the caller to pass issues for timing check.
    # For now, use evidence signals only.
    has_timing = evidence.get("_has_timing", True)  # default true if unknown

    # Path 1: Standard — temporal grounding + corroboration
    if has_timing:
        temporally_grounded = evidence["temporal_alignment"]["score"] >= 2
        if temporally_grounded and _is_corroborated(evidence):
            if degradation_window:
                return ("active_incident", 0)
            else:
                # Persistent path: no window, but sustained activity.
                # Requires STRONGER corroboration to avoid flagging
                # healthy background errors as incidents.
                if _is_strongly_corroborated(evidence):
                    return ("persistent_failure", 0)
                # Otherwise: sustained but not sufficiently corroborated
                # → not an incident

    # Path 2: Missing timing — requires stronger corroboration
    # Missing timing is NOT positive evidence; bar is higher.
    if not has_timing and _is_strongly_corroborated(evidence):
        return ("persistent_failure", 0)

    return ("none", None)


def _shares_infrastructure(issue_a, issue_b):
    """Do two issues share pool or db_node?"""
    for field in ("pool", "db_node"):
        a_vals = set(issue_a.get("correlation", {}).get(field, []))
        b_vals = set(issue_b.get("correlation", {}).get(field, []))
        if a_vals & b_vals:
            return True
    return False


def _has_contributor_signal(evidence):
    """Adjustment B: Possible contributors need more than shared infra.

    Requires resource pressure, relevant semantics (specificity), or
    temporal ordering — not just a shared pool identifier.
    """
    return (
        evidence["resource_pressure"]["score"] >= 1 or
        evidence["specificity"]["score"] >= 1
    )


def build_supporting_evidence(leader_template, leader_issue, ranked, issues,
                               degradation_window):
    """Phase D: Surface related evidence without changing rankings.

    Returns dict with observed / correlated / hypothesized lists.
    Each item: (template, count, level, one_liner).
    Capped at 3 per subsection for initial display.
    """
    observed = []
    correlated = []
    hypothesized = []

    for template, score, evidence in ranked:
        if template == leader_template:
            continue
        issue = issues[template]
        shares_infra = _shares_infrastructure(leader_issue, issue)
        temporally_aligned = evidence["temporal_alignment"]["score"] >= 2

        one_liner = f"{issue['level']} x{issue['count']}"

        if shares_infra and _has_contributor_signal(evidence):
            # Possible contributor: shares infra AND has additional signal
            hypothesized.append((template, issue["count"],
                                 issue["level"], one_liner))
        elif shares_infra:
            # Shares infra but no contributor signal → observed correlation
            observed.append((template, issue["count"],
                             issue["level"], one_liner))
        elif temporally_aligned:
            correlated.append((template, issue["count"],
                               issue["level"], one_liner))

    return {
        "observed": observed[:3],
        "correlated": correlated[:3],
        "hypothesized": hypothesized[:3],
        "observed_total": len(observed),
        "correlated_total": len(correlated),
        "hypothesized_total": len(hypothesized),
    }


def build_incident_section(ranked, issues, degradation_window, timeline_buckets):
    """Phase D: Build the incident_section for the API response."""
    section_type, candidate_idx = classify_incident_section(
        ranked, degradation_window
    )

    if section_type == "none":
        return {
            "type": "none",
            "headline": None,
            "message": (
                "No active incident established from the available log evidence. "
                "No escalation was detected in this log. This does not guarantee "
                "the system is healthy — persistent issues may not produce spikes."
            ),
        }

    template, score, evidence = ranked[candidate_idx]
    issue = issues[template]

    # Starting point: db_node and pool if available
    db_nodes = issue.get("correlation", {}).get("db_node", [])
    pools = issue.get("correlation", {}).get("pool", [])
    starting_point = " · ".join(filter(None, [
        db_nodes[0] if db_nodes else None,
        pools[0] if pools else None,
    ]))

    supporting = build_supporting_evidence(
        template, issue, ranked, issues, degradation_window
    )

    # Group ALL supporting evidence by family (before display capping)
    # Rebuild full lists without the 3-item cap for grouping
    full_observed, full_correlated, full_hypothesized = [], [], []
    for t2, s2, e2 in ranked:
        if t2 == template:
            continue
        issue2 = issues[t2]
        shares = _shares_infrastructure(issue, issue2)
        aligned = e2["temporal_alignment"]["score"] >= 2
        if shares and _has_contributor_signal(e2):
            full_hypothesized.append((t2, issue2["count"], issue2["level"]))
        elif shares:
            full_observed.append((t2, issue2["count"], issue2["level"]))
        elif aligned:
            full_correlated.append((t2, issue2["count"], issue2["level"]))

    all_for_grouping = (
        [(t, c, l, "") for t, c, l in full_observed] +
        [(t, c, l, "") for t, c, l in full_correlated] +
        [(t, c, l, "") for t, c, l in full_hypothesized]
    )
    family_groups = group_evidence_by_family(all_for_grouping, issues)

    # Other qualifying candidates with different infrastructure
    other_candidates = []
    for idx, (t2, s2, e2) in enumerate(ranked[1:4], start=1):
        if t2 == template:
            continue
        issue2 = issues[t2]
        if not _shares_infrastructure(issue, issue2):
            # Different infra — potentially separate incident
            stype, _ = classify_incident_section(
                [(t2, s2, e2)], degradation_window
            )
            if stype != "none":
                other_candidates.append({
                    "template": t2[:80],
                    "level": issue2["level"],
                    "count": issue2["count"],
                })
        if len(other_candidates) >= 3:
            break

    type_label = (
        "active_incident" if section_type == "active_incident"
        else "persistent_failure"
    )
    headline_prefix = (
        "Active incident" if section_type == "active_incident"
        else "Persistent failure activity"
    )

    return {
        "type": type_label,
        "headline": headline_prefix,
        "investigate_first": template[:120],
        "starting_point": starting_point or "Unknown",
        "supporting_evidence": supporting,
        "family_groups": family_groups,
        "other_candidates": other_candidates,
        "timing_note": (
            None if evidence.get("_has_timing", True)
            else "Timing unavailable — temporal ordering unknown."
        ),
    }


def build_notable_events(ranked, issues, incident_templates):
    """Phase D: Issues worth reviewing but not in incident investigation."""
    notable = []
    for template, score, evidence in ranked:
        if template in incident_templates:
            continue
        issue = issues[template]
        # Include CRITICAL/ERROR, or top-ranked WARNs
        if issue["level"] in ("CRITICAL", "ERROR") or len(notable) < 5:
            notable.append({
                "template": template[:100],
                "level": issue["level"],
                "count": issue["count"],
                "score": round(score, 1),
            })
        if len(notable) >= 10:
            break
    return notable


# --- Phase D: Event family grouping (presentation only) ------------------

def _normalize_family(template):
    """Group templates by event family, collapsing format variations.

    Generic across log formats — uses semantic keywords, not benchmark-
    specific patterns. Two templates from different formats (JSON vs
    logfmt) describing the same event map to the same family.
    """
    t = template.lower()
    # Order matters: check specific before general
    if "transaction_hold" in t or ("held_ms" in t and "hold" in t):
        return "transaction_hold"
    if "pool_sample" in t or "pool_saturation" in t or "pool_snapshot" in t:
        return "pool_pressure"
    if "db_acquire" in t or "acquire_timeout" in t or "acquire_failed" in t:
        return "db_acquire"
    if "connection_" in t and ("timeout" in t or "failed" in t or "refused" in t):
        return "connection_failure"
    if "checkout" in t:
        return "checkout_failure"
    if "order" in t and ("fail" in t or "timeout" in t or "error" in t):
        return "order_failure"
    if "payment" in t and ("fail" in t or "timeout" in t or "retry" in t):
        return "payment_failure"
    # Fallback: use first significant token
    return "other"


# Family display metadata: role labels and deterministic order.
# Order is by evidence role, not by score — avoids recreating the
# visibility problem through score-based sorting.
_FAMILY_INFO = {
    "transaction_hold": {
        "label": "Long-held transactions",
        "role": "possible_contributor",
        "role_label": "Possible contributor",
        "order": 1,
    },
    "pool_pressure": {
        "label": "Pool saturation",
        "role": "observed",
        "role_label": "Observed resource pressure",
        "order": 2,
    },
    "db_acquire": {
        "label": "DB acquisition timeouts",
        "role": "observed",
        "role_label": "Observed failures",
        "order": 3,
    },
    "connection_failure": {
        "label": "Connection failures",
        "role": "observed",
        "role_label": "Observed failures",
        "order": 3,
    },
    "checkout_failure": {
        "label": "Checkout failures",
        "role": "downstream",
        "role_label": "Downstream symptoms",
        "order": 4,
    },
    "order_failure": {
        "label": "Order failures",
        "role": "downstream",
        "role_label": "Downstream symptoms",
        "order": 4,
    },
    "payment_failure": {
        "label": "Payment failures",
        "role": "downstream",
        "role_label": "Downstream symptoms",
        "order": 4,
    },
    "other": {
        "label": "Other events",
        "role": "downstream",
        "role_label": "Other",
        "order": 5,
    },
}


def group_evidence_by_family(evidence_items, issues):
    """Group supporting evidence items by event family.

    Presentation-only: does not modify scores or discard entries.
    Returns list of family groups, ordered deterministically by
    evidence role (not by score).

    Each group: {
        "family": str, "label": str, "role": str, "role_label": str,
        "template_count": int,  # number of templates (not occurrences)
        "total_occurrences": int,  # sum of issue counts
        "max_telemetry": dict,  # e.g. {"held_ms": 175371}
        "pools": [...], "db_nodes": [...],
        "members": [(template, count, level), ...],  # all preserved
    }
    """
    families = {}
    for template, count, level, _one_liner in evidence_items:
        family = _normalize_family(template)
        if family not in families:
            families[family] = []
        families[family].append((template, count, level))

    groups = []
    for family, members in families.items():
        info = _FAMILY_INFO.get(family, _FAMILY_INFO["other"])
        # Aggregate telemetry max and infrastructure
        max_tele = {}
        pools = set()
        nodes = set()
        total_occ = 0
        for template, count, level in members:
            # Find the issue for this template
            # (issues dict passed separately; match by template prefix)
            total_occ += count
            for t_key, issue in issues.items():
                if t_key == template or t_key.startswith(template[:40]):
                    tele = issue.get("telemetry", {})
                    for field, vals in tele.items():
                        if isinstance(vals, dict) and "max" in vals:
                            cur = max_tele.get(field, float("-inf"))
                            if vals["max"] > cur:
                                max_tele[field] = vals["max"]
                    pools.update(issue.get("correlation", {}).get("pool", []))
                    nodes.update(issue.get("correlation", {}).get("db_node", []))
                    break

        groups.append({
            "family": family,
            "label": info["label"],
            "role": info["role"],
            "role_label": info["role_label"],
            "order": info["order"],
            "template_count": len(members),
            "total_occurrences": total_occ,
            "max_telemetry": max_tele,
            "pools": sorted(pools),
            "db_nodes": sorted(nodes),
            "members": members,  # all preserved for drill-down
        })

    # Deterministic order by role, then family name
    groups.sort(key=lambda g: (g["order"], g["family"]))
    return groups
