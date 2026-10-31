"""Compare two logs (issue #102, Release #3) — pure diff logic.

This module is deliberately free of HTTP, database, and ledger concerns:
it turns two structured ``analyze_log_file`` results (plus their opt-in
comparison evidence) into the stored comparison payload defined by the
approved #102 spec §4. Routes, consent, and charging live in ``main.py``
and ``credits.py`` in a later slice of the same PR; nothing here debits,
reserves, or persists anything.

Design rules (approved spec, binding trims C3/C8/C9):
- Identity is the exact ``normalize_issue()`` output (the ``issues`` dict
  key), independent of severity and input role. No fuzzy matching, no
  service dimension in v1.
- "Resolved" means absent from B, not proof an underlying fault was
  fixed; that wording is stored on the payload for renderers.
- WARN groups are labeled as warnings, never as errors; INFO-to-ERROR
  appears as a new group because INFO has no issue group to match.
- Severity is the HIGHEST observed severity from the per-group level
  distribution, never the first-occurrence ``level``. When evidence is
  absent (e.g. a legacy result), the group's first-occurrence level is
  used as a single-level distribution as a documented fallback.
- Material volume change (v1 policy, adjustable): |B - A| >= 5 AND
  |B - A| / A >= 0.5. Threshold values and version are stored on the
  payload. New/resolved groups never enter the volume/severity
  categories (no division by zero, no double counting).
- No diagnostic scores or internal classification tokens appear anywhere
  in the payload.
"""

from __future__ import annotations

import os

# Approved spec §4 / trim C3: material-change policy v1 (adjustable).
MATERIAL_VERSION = 1
MATERIAL_MIN_ABSOLUTE = 5
MATERIAL_MIN_FRACTION_OF_A = 0.5

MATCHING_VERSION = 1
SCHEMA_VERSION = 1

# Highest-observed-severity ordering: WARN < ERROR < CRITICAL.
_SEVERITY_RANK = {"WARN": 1, "ERROR": 2, "CRITICAL": 3}

RESOLVED_NOTE = (
    "Resolved means the pattern was not observed in B; it is not proof "
    "that an underlying fault was fixed."
)


def highest_severity(level_counts: dict) -> str | None:
    """Highest observed severity in a per-group level distribution."""
    best = None
    for level, count in (level_counts or {}).items():
        if count and level in _SEVERITY_RANK:
            if best is None or _SEVERITY_RANK[level] > _SEVERITY_RANK[best]:
                best = level
    return best


def _side_evidence(evidence: dict | None, template: str) -> dict:
    if evidence and template in evidence:
        return evidence[template]
    return {}


def _level_distribution(group: dict | None, evidence_entry: dict) -> dict:
    """Per-group severity distribution, with a documented fallback.

    With evidence, this is the collector's exact distribution. Without
    it, the group's first-occurrence level stands in as a single-level
    distribution so the diff still runs for legacy results.
    """
    if evidence_entry and evidence_entry.get("level_counts"):
        return dict(evidence_entry["level_counts"])
    if group and group.get("level") in _SEVERITY_RANK:
        return {group["level"]: group.get("count", 0)}
    return {}


def _examples(evidence_entry: dict) -> dict:
    if evidence_entry:
        return {
            level: list(examples)
            for level, examples in (evidence_entry.get("examples") or {}).items()
        }
    return {}


def _side_summary(result: dict, role: str, filename: str) -> dict:
    return {
        "role": role,
        "filename": filename,
        "total_lines": result.get("total_lines", 0),
        "parsed_lines": result.get("parsed_lines", 0),
        "malformed_lines": result.get("malformed_lines", 0),
        "level_counts": dict(result.get("level_counts") or {}),
        "service_counts": dict(result.get("service_counts") or {}),
        "first_seen": result.get("first_seen"),
        "last_seen": result.get("last_seen"),
    }


def _entry(template: str, a_group, b_group, a_ev, b_ev) -> dict:
    a_levels = _level_distribution(a_group, a_ev)
    b_levels = _level_distribution(b_group, b_ev)
    a_count = a_group["count"] if a_group else 0
    b_count = b_group["count"] if b_group else 0
    return {
        "template": template,
        "a_count": a_count,
        "b_count": b_count,
        "a_level_counts": a_levels,
        "b_level_counts": b_levels,
        "a_highest_severity": highest_severity(a_levels),
        "b_highest_severity": highest_severity(b_levels),
        "a_examples": _examples(a_ev),
        "b_examples": _examples(b_ev),
        "a_first_seen": a_group.get("first_seen") if a_group else None,
        "b_first_seen": b_group.get("first_seen") if b_group else None,
        "a_last_seen": a_group.get("last_seen") if a_group else None,
        "b_last_seen": b_group.get("last_seen") if b_group else None,
        "a_services": list(a_group.get("services") or []) if a_group else [],
        "b_services": list(b_group.get("services") or []) if b_group else [],
        "examples_truncated": bool(
            (a_ev and a_ev.get("examples_truncated"))
            or (b_ev and b_ev.get("examples_truncated"))
        ),
    }


def _sort_key(entry: dict, severity_field: str, count_field: str):
    """Deterministic ordering: severity desc, |count delta| desc, template."""
    severity = entry.get(severity_field)
    rank = _SEVERITY_RANK.get(severity, 0)
    delta = abs(entry["b_count"] - entry["a_count"])
    return (-rank, -delta, entry["template"])


def compare_results(a_result: dict, b_result: dict,
                    a_evidence: dict | None = None,
                    b_evidence: dict | None = None) -> dict:
    """Diff two analyzer results into the stored comparison payload.

    ``a_evidence``/``b_evidence`` default to the results' own
    ``comparison_evidence`` key when present. Direction is fixed A -> B:
    A is Before/baseline, B is After.
    """
    if a_evidence is None:
        a_evidence = a_result.get("comparison_evidence") or {}
    if b_evidence is None:
        b_evidence = b_result.get("comparison_evidence") or {}
    a_issues = a_result.get("issues") or {}
    b_issues = b_result.get("issues") or {}

    a_name = os.path.basename(str(a_result.get("file", "A.log")))
    b_name = os.path.basename(str(b_result.get("file", "B.log")))

    new, resolved, shared = [], [], []
    volume_changes, severity_shifts = [], []
    for template in sorted(set(a_issues) | set(b_issues)):
        a_group = a_issues.get(template)
        b_group = b_issues.get(template)
        entry = _entry(template, a_group, b_group,
                       _side_evidence(a_evidence, template),
                       _side_evidence(b_evidence, template))
        if a_group is None:
            new.append(entry)
        elif b_group is None:
            resolved.append(entry)
        else:
            shared.append(entry)
            delta = abs(entry["b_count"] - entry["a_count"])
            if (delta >= MATERIAL_MIN_ABSOLUTE
                    and delta / entry["a_count"] >= MATERIAL_MIN_FRACTION_OF_A):
                volume_changes.append(entry)
            if (entry["a_highest_severity"] != entry["b_highest_severity"]
                    and entry["a_highest_severity"] is not None
                    and entry["b_highest_severity"] is not None):
                severity_shifts.append(entry)

    new.sort(key=lambda e: _sort_key(e, "b_highest_severity", "b_count"))
    resolved.sort(key=lambda e: _sort_key(e, "a_highest_severity", "a_count"))
    shared.sort(key=lambda e: _sort_key(e, "b_highest_severity", "b_count"))
    volume_changes.sort(key=lambda e: _sort_key(e, "b_highest_severity", "b_count"))
    severity_shifts.sort(key=lambda e: _sort_key(e, "b_highest_severity", "b_count"))

    return {
        "report_kind": "comparison",
        "schema_version": SCHEMA_VERSION,
        "matching_version": MATCHING_VERSION,
        "filename": f"{a_name} → {b_name}",
        "inputs": {
            "a": _side_summary(a_result, "before", a_name),
            "b": _side_summary(b_result, "after", b_name),
        },
        "material_change": {
            "version": MATERIAL_VERSION,
            "min_absolute": MATERIAL_MIN_ABSOLUTE,
            "min_fraction_of_a": MATERIAL_MIN_FRACTION_OF_A,
        },
        "summary": {
            "new": len(new),
            "resolved": len(resolved),
            "volume_changed": len(volume_changes),
            "severity_shifted": len(severity_shifts),
        },
        "new": new,
        "resolved": resolved,
        "volume_changes": volume_changes,
        "severity_shifts": severity_shifts,
        "shared": shared,
        "no_material_differences": not (new or resolved or volume_changes
                                        or severity_shifts),
        "resolved_note": RESOLVED_NOTE,
    }
