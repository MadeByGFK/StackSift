"""Issue #106 Stage 2: paid Analysis Report generation.

Deterministic, evidence-backed explanation of an existing completed
single-file analysis, built ONLY from the retained diagnostic-evidence
contract Stage 1 captures (``results.diagnostic_evidence``). No LLM, no
re-parse of raw logs, no invented facts: every explanatory claim carries
machine-checkable references to retained fields/excerpts, likely-cause
framing is bounded to reviewed rules, and when no rule is supported the
generator abstains with the ruled sentence.

User-facing name (founder ruling 2026-11-03): "Analysis Report", action
label "Analysis". "Deep-dive" survives only in internal identifiers
(this module, the ``deep_dive`` operation/result type, COST_DEEP_DIVE).

Content standard (2026-10-11): no diagnostic scores and no internal
evidence labels (signal keys, tier/classifier labels) anywhere in the
stored presentation projection, HTML, PDF, CSV or JSON.
"""

from __future__ import annotations

import csv
import io
import json
import time

# Internal identifiers (never user-facing copy).
REPORT_KIND = "deep_dive"
SCHEMA_VERSION = 1
GENERATOR_VERSION = "106-stage2-v1"

# Generation bounds (spec: adjustable policy, enforced before charge
# where possible and again at generation). Aligned with Stage 1's
# retained-evidence bounds.
MAX_GROUPS = 1000
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
GENERATION_DEADLINE_SECONDS = 25.0

# Founder-approved legacy message, reworded only for the ruled
# user-facing name (Sunny amendment 6612309982: "deep-dive" never
# appears in user-facing copy).
LEGACY_MESSAGE = (
    "This report does not retain enough evidence for an Analysis "
    "Report. Analyze the original log again to create an eligible "
    "report."
)

ABSTENTION = "The retained evidence does not establish the cause."

UNSUPPORTED_KINDS = ("comparison", "batch", "deep_dive")


class AnalysisError(ValueError):
    """Base: the source cannot produce an Analysis Report."""


class UnsupportedReportKind(AnalysisError):
    """Compare/batch/Analysis-Report sources reject before reservation."""


class InsufficientEvidence(AnalysisError):
    """Legacy or partially evidenced sources reject before reservation."""


def source_report_kind(payload) -> str | None:
    if not isinstance(payload, dict):
        return None
    return payload.get("report_kind")


def check_source_kind(payload) -> None:
    """Fail closed on unsupported report kinds (before any charge)."""
    kind = source_report_kind(payload)
    if kind in UNSUPPORTED_KINDS:
        raise UnsupportedReportKind(
            "Analysis Reports are not available for this report type")
    if kind is not None and kind not in ("single", "analysis"):
        raise UnsupportedReportKind(
            "Analysis Reports are not available for this report type")


def retained_evidence(payload) -> dict | None:
    if not isinstance(payload, dict):
        return None
    results = payload.get("results")
    if not isinstance(results, dict):
        return None
    evidence = results.get("diagnostic_evidence")
    return evidence if isinstance(evidence, dict) else None


def _issue_map(payload) -> dict:
    results = payload.get("results") if isinstance(payload, dict) else None
    issues = results.get("issues") if isinstance(results, dict) else None
    return issues if isinstance(issues, dict) else {}


def _coverage_map(evidence: dict) -> dict:
    """Per-template severity metadata: excerpt groups, falling back to
    the always-complete severity_metadata map Stage 1 retains."""
    coverage = {}
    for template, group in (evidence.get("groups") or {}).items():
        if isinstance(group, dict):
            coverage[template] = group
    for template, meta in (evidence.get("severity_metadata") or {}).items():
        if template not in coverage and isinstance(meta, dict):
            coverage[template] = {
                "level_counts": meta.get("level_counts") or {},
                "peak_level": meta.get("peak_level"),
                "excerpts": [],
                "excerpts_truncated": True,
            }
    return coverage


def check_eligibility(payload) -> dict:
    """Validate the retained-evidence contract; return the evidence.

    Raises UnsupportedReportKind / InsufficientEvidence. Pure: no
    generation, no charge-side effects, safe to run before reservation.
    """
    check_source_kind(payload)
    evidence = retained_evidence(payload)
    if evidence is None:
        raise InsufficientEvidence(LEGACY_MESSAGE)
    if evidence.get("schema_version") != 1 or not evidence.get("grouping_version"):
        raise InsufficientEvidence(LEGACY_MESSAGE)
    issues = _issue_map(payload)
    if not issues:
        raise InsufficientEvidence(LEGACY_MESSAGE)
    if len(issues) > MAX_GROUPS:
        raise InsufficientEvidence(
            "This report has too many issue groups for an Analysis Report.")
    try:
        evidence_bytes = len(json.dumps(evidence).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise InsufficientEvidence(LEGACY_MESSAGE) from exc
    if evidence_bytes > MAX_EVIDENCE_BYTES:
        raise InsufficientEvidence(
            "This report retains too much evidence for an Analysis Report.")
    coverage = _coverage_map(evidence)
    # Coverage rule: every group being explained must be backed by
    # retained severity metadata. A group with no retained record at
    # all cannot be explained honestly, so the report is ineligible
    # rather than partially sold.
    if any(template not in coverage for template in issues):
        raise InsufficientEvidence(LEGACY_MESSAGE)
    return evidence


def is_eligible(payload) -> bool:
    try:
        check_eligibility(payload)
        return True
    except AnalysisError:
        return False


def eligibility_state(payload) -> tuple[bool, str | None]:
    """(eligible, user-facing reason when not)."""
    try:
        check_eligibility(payload)
        return True, None
    except UnsupportedReportKind:
        return False, "Analysis Reports are not available for this report type."
    except InsufficientEvidence as exc:
        return False, str(exc)


def analysis_request_hash(source_result, payload) -> str:
    """Canonical server-owned identity for one Analysis generation.

    Binds owner-visible source identity + integrity digest + the
    grouping/evidence/generator/schema versions (spec: canonical
    identity). The client cannot select any component.
    """
    from app import credits
    evidence = retained_evidence(payload) or {}
    return credits.hash_input(json.dumps(
        {
            "action_kind": "deep_dive",
            "source_result_id": str(source_result.id),
            "source_integrity_digest": source_result.integrity_digest,
            "grouping_version": evidence.get("grouping_version"),
            "evidence_schema_version": evidence.get("schema_version"),
            "generator_version": GENERATOR_VERSION,
            "schema_version": SCHEMA_VERSION,
        },
        sort_keys=True, separators=(",", ":"),
    ).encode())


# ---------------------------------------------------------------------------
# Deterministic explanation rules. Each rule reads ONLY the template text
# and retained structured fields. Cause language stays bounded ("can
# occur when", never "caused by" / "crashed" / outage claims).
# ---------------------------------------------------------------------------

def _claim(text, refs):
    return {"text": text, "evidence_refs": list(refs)}


def _symptom_and_cause(template: str, refs):
    low = template.lower()
    # F1 (PR #139 remediation): predicates must require BOTH the
    # relevant context AND failure semantics. A bare "refused" (e.g.
    # "Payment refused by fraud policy") does not establish a refused
    # network connection, and a bare "exhausted" (e.g. "Disk space
    # exhausted") or a bare pool mention (e.g. "Connection pool
    # reconfigured successfully") does not establish pool exhaustion.
    # Unsupported shapes fall through to the default/abstention
    # branch below.
    _has_connection_context = (
        "connection" in low or "connect" in low)
    _has_refused_failure = "refused" in low
    if _has_refused_failure and _has_connection_context:
        return (
            "The retained messages record connection attempts that "
            "were refused by the destination.",
            "A refused connection can occur when the destination is "
            "not accepting connections at that moment; the retained "
            "evidence does not establish why it refused.",
            "Check whether the destination recorded in the retained "
            "excerpts was accepting connections at the recorded times.",
        )
    if "timed out" in low or "timeout" in low:
        return (
            "The retained messages record operations that timed out "
            "before completing.",
            "A timeout can occur when the other side is slower than "
            "the waiting limit allows; the retained evidence does not "
            "establish where the time was spent.",
            "Check the recorded time span for this group and whether "
            "the same service shows related timeout messages.",
        )
    _has_pool_context = "pool" in low
    _has_exhaustion_failure = (
        "exhausted" in low or "exhaustion" in low
        or "no connections available" in low
        or "no available connections" in low
        or "out of connections" in low)
    if _has_pool_context and _has_exhaustion_failure:
        return (
            "The retained messages record a resource pool reporting "
            "that it was exhausted.",
            "Pool exhaustion can occur when concurrent demand exceeds "
            "the configured pool size; the retained evidence does not "
            "establish what held the connections.",
            "Check which services appear in the retained excerpts for "
            "this group around the recorded times.",
        )
    if "declined" in low:
        return (
            "The retained messages record transactions that were "
            "declined.",
            None,
            "Check the retained excerpts for the decline wording that "
            "repeats across this group.",
        )
    return (
        "The retained excerpts show this message exactly as recorded; "
        "no further symptom detail is established by the evidence.",
        None,
        "Start from the retained excerpts for this group and check "
        "the recorded service at the recorded times.",
    )


def _group_projection(template, group, evidence_group):
    level = group.get("level") or evidence_group.get("peak_level") or ""
    count = group.get("count") or 0
    services = group.get("services") or []
    first_seen = group.get("first_seen")
    last_seen = group.get("last_seen")
    excerpts = evidence_group.get("excerpts") or []
    excerpt_refs = [e.get("evidence_id") for e in excerpts if e.get("evidence_id")]
    base_refs = [f"issue:{template}"] + excerpt_refs

    observations = []
    span = ""
    if first_seen and last_seen:
        span = f" First recorded at {first_seen}; last recorded at {last_seen}."
    svc_text = (
        " across service(s) " + ", ".join(str(s) for s in services)
        if services else "")
    observations.append(_claim(
        f"\"{template}\" was recorded {count} time(s) with peak "
        f"severity {level}{svc_text}.{span}", base_refs))
    level_counts = evidence_group.get("level_counts") or {}
    if level_counts:
        dist = ", ".join(
            f"{lvl}: {n}" for lvl, n in sorted(level_counts.items()))
        observations.append(_claim(
            f"Observed severities for this group: {dist}.",
            [f"issue:{template}"]))

    symptom, cause, check = _symptom_and_cause(template, base_refs)
    explanations = [_claim(symptom, base_refs)]
    possible_causes = [_claim(cause, base_refs)] if cause else [
        _claim(ABSTENTION, base_refs)]
    first_checks = [_claim(check, base_refs)]

    limitations = []
    if not excerpts:
        limitations.append(
            "No retained excerpt is available for this group; the "
            "explanation rests on the retained counts and fields only.")
    if evidence_group.get("excerpts_truncated"):
        limitations.append(
            "Only a sample of this group's messages was retained; "
            "the excerpts may not show every variant.")
    if not first_seen or not last_seen:
        limitations.append(
            "Some messages in this group have no recorded timestamp, "
            "so ordering across groups cannot be established.")
    if not services:
        limitations.append(
            "No service was recorded for this group.")

    return {
        "template": template,
        "count": count,
        "level": level,
        "services": [str(s) for s in services],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observations": observations,
        "explanations": explanations,
        "possible_causes": possible_causes,
        "first_checks": first_checks,
        "excerpts": [
            {
                "analysis_line_number": e.get("analysis_line_number"),
                "text": e.get("text") or "",
                "timestamp": e.get("timestamp"),
                "service": e.get("service"),
                "level": e.get("level"),
                "text_truncated": bool(e.get("text_truncated")),
            }
            for e in excerpts
        ],
        "limitations": limitations,
        # Internal audit refs: stored for verification, stripped from
        # every user-facing projection (see public_projection()).
        "_evidence_refs": excerpt_refs,
    }


def build_deep_dive(source_payload, *, source_result_id=None,
                    source_integrity_digest=None,
                    deadline_seconds=GENERATION_DEADLINE_SECONDS,
                    clock=time.monotonic):
    """Build the Analysis Report artifact from a validated snapshot.

    Raises InsufficientEvidence / UnsupportedReportKind for ineligible
    sources and AnalysisError when generation exceeds its deadline
    (the caller releases the reservation: net charge 0).
    """
    started = clock()
    evidence = check_eligibility(source_payload)
    issues = _issue_map(source_payload)
    coverage = _coverage_map(evidence)
    sorted_issues = source_payload.get("sorted_issues")
    if isinstance(sorted_issues, list) and sorted_issues:
        ordered = [entry[0] for entry in sorted_issues
                   if isinstance(entry, (list, tuple)) and entry]
        ordered += [t for t in issues if t not in ordered]
    else:
        ordered = sorted(issues)
    groups = []
    for template in ordered:
        if clock() - started > deadline_seconds:
            raise AnalysisError("generation deadline exceeded")
        groups.append(_group_projection(
            template, issues[template], coverage[template]))
    total = sum(g["count"] for g in groups)
    summary = (
        f"{len(groups)} issue group(s), {total} recorded occurrence(s) "
        f"explained from the retained evidence of the source report.")
    return {
        "report_kind": REPORT_KIND,
        "schema_version": SCHEMA_VERSION,
        "source_result_id": str(source_result_id) if source_result_id else None,
        "source_integrity_digest": source_integrity_digest,
        "grouping_version": evidence.get("grouping_version"),
        "evidence_schema_version": evidence.get("schema_version"),
        "generator_version": GENERATOR_VERSION,
        "filename": source_payload.get("filename"),
        "summary": summary,
        "groups": groups,
        "elapsed": round(clock() - started, 3),
    }


# ---------------------------------------------------------------------------
# Presentation projections — the ONLY shapes HTML/PDF/CSV/JSON may use.
# Internal refs, digests and provenance internals never cross here.
# ---------------------------------------------------------------------------

def public_projection(artifact) -> dict:
    if not isinstance(artifact, dict) or artifact.get("report_kind") != REPORT_KIND:
        raise AnalysisError("not an Analysis Report artifact")
    groups = []
    for group in artifact.get("groups") or []:
        groups.append({
            "template": group.get("template"),
            "count": group.get("count"),
            "level": group.get("level"),
            "services": group.get("services") or [],
            "first_seen": group.get("first_seen"),
            "last_seen": group.get("last_seen"),
            "observations": [c["text"] for c in group.get("observations") or []],
            "explanations": [c["text"] for c in group.get("explanations") or []],
            "possible_causes": [c["text"] for c in group.get("possible_causes") or []],
            "first_checks": [c["text"] for c in group.get("first_checks") or []],
            "excerpts": [
                {
                    "analysis_line_number": e.get("analysis_line_number"),
                    "text": e.get("text"),
                    "timestamp": e.get("timestamp"),
                    "service": e.get("service"),
                    "level": e.get("level"),
                    "text_truncated": bool(e.get("text_truncated")),
                }
                for e in group.get("excerpts") or []
            ],
            "limitations": list(group.get("limitations") or []),
        })
    return {
        "report_kind": REPORT_KIND,
        "display_name": "Analysis Report",
        "schema_version": artifact.get("schema_version"),
        "filename": artifact.get("filename"),
        "summary": artifact.get("summary"),
        "groups": groups,
        "elapsed": artifact.get("elapsed"),
    }


def validate_artifact(manifest, *, expected_source_id=None,
                      expected_source_integrity_digest=None) -> dict:
    """Validate a stored Analysis artifact manifest; return it or raise."""
    if not isinstance(manifest, dict):
        raise AnalysisError("invalid Analysis Report artifact")
    if manifest.get("report_kind") != REPORT_KIND:
        raise AnalysisError("not an Analysis Report artifact")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise AnalysisError("unsupported Analysis Report schema version")
    if expected_source_id is not None and \
            manifest.get("source_result_id") != str(expected_source_id):
        raise AnalysisError("artifact source mismatch")
    if expected_source_integrity_digest is not None and \
            manifest.get("source_integrity_digest") != expected_source_integrity_digest:
        raise AnalysisError("artifact source integrity digest mismatch")
    if not isinstance(manifest.get("groups"), list):
        raise AnalysisError("artifact groups missing")
    return manifest


def projection_to_csv(projection) -> bytes:
    """CSV projection: one row per group (issue table shape)."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=",", lineterminator="\r\n")
    writer.writerow(["template", "level", "count", "services",
                     "first_seen", "last_seen"])
    for group in projection.get("groups") or []:
        writer.writerow([
            group.get("template") or "",
            group.get("level") or "",
            group.get("count") or 0,
            json.dumps(group.get("services") or [], ensure_ascii=False,
                       separators=(",", ":")),
            group.get("first_seen") or "",
            group.get("last_seen") or "",
        ])
    return output.getvalue().encode("utf-8")


def projection_to_json(projection) -> bytes:
    text = json.dumps(projection, ensure_ascii=False, allow_nan=False)
    return f"{text}\n".encode("utf-8")


def projection_text_lines(projection) -> list[str]:
    """Plain-language lines for the PDF renderer."""
    lines = [projection.get("summary") or ""]
    for group in projection.get("groups") or []:
        lines.append("")
        lines.append(f"[{group.get('level')}] {group.get('template')} "
                     f"x {group.get('count')}")
        for section, key in (
                ("What was observed", "observations"),
                ("What this may mean", "possible_causes"),
                ("Explanation", "explanations"),
                ("Suggested first checks", "first_checks")):
            for text in group.get(key) or []:
                lines.append(f"{section}: {text}")
        for excerpt in group.get("excerpts") or []:
            lines.append(f"Evidence (analysis line "
                         f"{excerpt.get('analysis_line_number')}): "
                         f"{excerpt.get('text')}")
        for limit in group.get("limitations") or []:
            lines.append(f"Limit: {limit}")
    return lines
