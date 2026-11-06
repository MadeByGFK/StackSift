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
GENERATOR_VERSION = "162-brief-v1"

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

# Issue #162: Investigation Brief constants. Every generated sentence
# in the brief is either one of these constants or is assembled in
# _build_brief from the sentence->source-field map in the #162 spec
# (as amended by Amendment A1); no other generated sentence is
# permitted.
BRIEF_SEQUENCE_CAPTION = (
    "Observed order in the log. This sequence shows what was "
    "recorded first, next, and last \u2014 it does not show that any "
    "event caused another.")
BRIEF_NOT_ESTABLISHED = (
    "This brief orders and summarizes what the log records. It does "
    "not establish the root cause of any event, and it does not "
    "establish that one recorded event caused another.")
BRIEF_WHY_LIMITATION = (
    "The brief does not re-rank findings; the ordering follows the "
    "free report's ranking, whose internal scoring is not part of "
    "this report.")
BRIEF_NO_SEQUENCE_LIMITATION = (
    "Timestamps were not recorded for these messages, so no observed "
    "sequence can be shown.")
BRIEF_NO_TIMESTAMPS_LIMITATION = (
    "Some groups have no recorded timestamp, so they do not appear "
    "in the observed sequence.")

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
    # F2 (PR #149 Codex P2): the timeout branch gets the same F1
    # treatment. A bare "timeout" mention is configuration or
    # negation as often as it is a failure — e.g. "Request timeout
    # disabled; operations will wait indefinitely" records no
    # timeout at all. Require failure semantics (the past-tense
    # event "timed out", or "timeout" paired with a failure noun)
    # and veto explicit configuration/negation shapes first;
    # anything else falls through to the abstention branch.
    _timeout_veto = (
        "timeout disabled" in low or "timeouts disabled" in low
        or "timeout is disabled" in low or "disable timeout" in low
        or "no timeout" in low or "not timed out" in low
        or "never timed out" in low or "without timing out" in low
        or "wait indefinitely" in low)
    _has_timeout_failure = (
        "timed out" in low
        or "timeout error" in low or "timeout exception" in low
        or "timeout exceeded" in low or "timeout expired" in low
        or "timeout occurred" in low or "timeout failure" in low
        or "timeout failed" in low)
    if _has_timeout_failure and not _timeout_veto:
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


def _claim_text(claims):
    """First claim's text from an internal claim list, or None.

    Internal group projections carry claims as {"text",
    "evidence_refs"} dicts (Amendment A1 / P1-1): the brief extracts
    .text explicitly and never copies a claim element verbatim.
    """
    if isinstance(claims, list) and claims:
        first = claims[0]
        if isinstance(first, dict) and isinstance(first.get("text"), str):
            return first["text"]
    return None


def _minute_key(first_seen):
    """Full-timestamp minute bucket (date + minute), or None.

    Amendment A1 / P2-4(c): same-minute comparisons use the full
    timestamp truncated to the minute, never clock minute across
    dates. Works for ISO strings ("2026-10-11T08:31:52.000Z" ->
    "2026-10-11T08:31") and "YYYY-MM-DD HH:MM:SS" shapes alike.
    """
    if not isinstance(first_seen, str) or len(first_seen) < 16:
        return None
    return first_seen[:16]


def _build_brief(payload, groups, coverage, *, started, clock,
                 deadline_seconds):
    """Issue #162: assemble the Investigation Brief.

    A projection over (a) the payload's retained free-synthesis
    fields and (b) the INTERNAL group projections built in this same
    run. Claim dicts are unwrapped via _claim_text; severity
    distribution comes from the coverage map; diagnostic_explanation
    strings are never rendered, quoted or paraphrased.
    """
    def _check_deadline():
        if clock() - started > deadline_seconds:
            raise AnalysisError("generation deadline exceeded")

    _check_deadline()
    if not isinstance(payload, dict):
        payload = {}

    # --- lead (decision 2): payload["diagnostic_issue"][0] ---------
    lead_template = None
    diagnostic_issue = payload.get("diagnostic_issue")
    if isinstance(diagnostic_issue, (list, tuple)) and diagnostic_issue:
        candidate = diagnostic_issue[0]
        if isinstance(candidate, str) and candidate:
            lead_template = candidate
    lead_group = None
    if lead_template is not None:
        for group in groups:
            if group.get("template") == lead_template:
                lead_group = group
                break
    lead_coverage = {}
    if lead_template is not None and isinstance(coverage, dict):
        entry = coverage.get(lead_template)
        if isinstance(entry, dict):
            lead_coverage = entry
    lead_level_counts = {}
    raw_counts = lead_coverage.get("level_counts")
    if isinstance(raw_counts, dict):
        for lvl, n in raw_counts.items():
            if isinstance(n, int):
                lead_level_counts[str(lvl)] = n

    limitations = []

    lead = None
    if lead_group is not None:
        lead = {
            "template": lead_template,
            "count": lead_group.get("count") or 0,
            "level": lead_group.get("level") or "",
            "level_counts": lead_level_counts,
            "services": [str(s) for s in lead_group.get("services") or []],
            "first_seen": lead_group.get("first_seen"),
            "last_seen": lead_group.get("last_seen"),
            "symptom": _claim_text(lead_group.get("explanations")),
            "cause": _claim_text(lead_group.get("possible_causes")),
            "excerpts": [
                {
                    "analysis_line_number": e.get("analysis_line_number"),
                    "text": e.get("text") or "",
                    "timestamp": e.get("timestamp"),
                    "service": e.get("service"),
                    "level": e.get("level"),
                    "text_truncated": bool(e.get("text_truncated")),
                }
                for e in (lead_group.get("excerpts") or [])[:2]
            ],
            "limitations": list(lead_group.get("limitations") or []),
        }

    # --- why-first (decision 3, as amended by A1/P2-5) --------------
    why_first = None
    if lead is not None:
        dist = ", ".join(
            f"{lvl}: {n}" for lvl, n in sorted(lead_level_counts.items()))
        facts = (
            f"Recorded facts for this group: {lead['count']} "
            f"occurrence(s); peak severity {lead['level'] or 'not recorded'}"
            + (f"; severity distribution {dist}" if dist else "")
            + (f"; first recorded at {lead['first_seen']}"
               if lead["first_seen"] else "")
            + (f"; last recorded at {lead['last_seen']}"
               if lead["last_seen"] else "")
            + ".")
        why_first = {
            "statement": (
                "This group is the same \"investigate first\" leader "
                "the free diagnostic ranking puts first for this file."),
            "facts": facts,
            "count": lead["count"],
            "level": lead["level"],
            "level_counts": dict(lead_level_counts),
            "first_seen": lead["first_seen"],
            "last_seen": lead["last_seen"],
            "limitation": BRIEF_WHY_LIMITATION,
        }

    _check_deadline()

    # --- observed sequence (decision 4) -----------------------------
    sequence = None
    timed = [(idx, g) for idx, g in enumerate(groups) if g.get("first_seen")]
    if timed:
        if len(timed) < len(groups):
            limitations.append(BRIEF_NO_TIMESTAMPS_LIMITATION)
        ordered_timed = sorted(
            timed, key=lambda pair: (pair[1]["first_seen"], pair[0]))
        selected = []
        seen_templates = set()
        # Lead first (wherever it falls), then earliest others.
        if lead_group is not None and lead_group.get("first_seen"):
            selected.append(lead_group)
            seen_templates.add(lead_group.get("template"))
        for _idx, group in ordered_timed:
            if len(selected) >= 8:
                break
            if group.get("template") in seen_templates:
                continue
            selected.append(group)
            seen_templates.add(group.get("template"))
        selected.sort(key=lambda g: (
            g.get("first_seen") or "",
            next(i for i, x in enumerate(groups) if x is g)))
        sequence = {
            "caption": BRIEF_SEQUENCE_CAPTION,
            "entries": [
                {
                    "template": g.get("template"),
                    "first_seen": g.get("first_seen"),
                    "last_seen": g.get("last_seen"),
                }
                for g in selected
            ],
        }
    else:
        limitations.append(BRIEF_NO_SEQUENCE_LIMITATION)

    _check_deadline()

    # --- priority checks (decision 5, as amended by A1/P2-4/P2-8) ---
    # Indexed lookups built in one pass: service -> groups and
    # minute-bucket -> groups. No all-pairs scan.
    service_index = {}
    minute_index = {}
    for group in groups:
        for svc in group.get("services") or []:
            service_index.setdefault(str(svc), []).append(group)
        minute = _minute_key(group.get("first_seen"))
        if minute:
            minute_index.setdefault(minute, []).append(group)

    def _motivation(group):
        excerpts = group.get("excerpts") or []
        if excerpts and isinstance(excerpts[0].get("text"), str) \
                and excerpts[0].get("text"):
            return excerpts[0]["text"]
        if group.get("first_seen"):
            text = f"First recorded at {group['first_seen']}"
            services = group.get("services") or []
            if services:
                text += f" in service {services[0]}"
            return text + "."
        # A1/P2-4(a): no timestamp -> non-temporal factual fallback;
        # a missing timestamp is never interpolated.
        return (
            f"Recorded {group.get('count') or 0} time(s) with peak "
            f"severity {group.get('level') or 'not recorded'}.")

    def _support(group):
        if group.get("first_seen"):
            return (
                f"Support: a retained excerpt at or after "
                f"{group['first_seen']} repeats this group's message. "
                f"The retained excerpts are a sample; absence there "
                f"does not count against this check.")
        return (
            "Support: a retained excerpt repeats this group's "
            "message. The retained excerpts are a sample; absence "
            "there does not count against this check.")

    def _weaken(group):
        if group.get("first_seen"):
            return (
                f"Weaken: no retained excerpt at or after "
                f"{group['first_seen']} repeats this group's message. "
                f"The retained excerpts are a sample; absence there "
                f"does not count against this check.")
        return (
            "Weaken: no retained excerpt repeats this group's "
            "message. The retained excerpts are a sample; absence "
            "there does not count against this check.")

    def _make_check(group, text):
        return {
            "template": group.get("template"),
            "text": text,
            "motivation": _motivation(group),
            "support": _support(group),
            "weaken": _weaken(group),
        }

    checks = []
    seen_check_texts = set()

    def _add_check(group, text, cap_for_group, added_for_group):
        if not text or added_for_group >= cap_for_group:
            return added_for_group
        normalized = " ".join(str(text).split()).lower()
        if normalized in seen_check_texts:
            return added_for_group
        seen_check_texts.add(normalized)
        checks.append(_make_check(group, text))
        return added_for_group + 1

    findings = []
    if lead_group is not None:
        findings.append((lead_group, 3, True))
    for group in groups:
        if len(findings) >= 3:
            break
        if lead_group is not None and group is lead_group:
            continue
        findings.append((group, 2, False))

    for group, cap, is_lead in findings:
        added = 0
        # Check A: the group's projected first check, verbatim text.
        added = _add_check(
            group, _claim_text(group.get("first_checks")), cap, added)
        if is_lead:
            # Check B: same-service, only the actual shared
            # intersection (A1/P2-4(b)).
            lead_services = [str(s) for s in group.get("services") or []]
            if lead_services and group.get("first_seen"):
                shared = sorted({
                    svc for svc in lead_services
                    for other in service_index.get(svc, [])
                    if other is not group
                })
                if shared:
                    added = _add_check(group, (
                        f"Check the other messages recorded for "
                        f"service(s) {', '.join(shared)} in this report "
                        f"around {group['first_seen']}."), cap, added)
            # Check C: same full-timestamp minute (A1/P2-4(c)).
            minute = _minute_key(group.get("first_seen"))
            if minute and any(
                    other is not group
                    for other in minute_index.get(minute, [])):
                added = _add_check(group, (
                    f"Check what else was first recorded at {minute} "
                    f"alongside this group."), cap, added)

    _check_deadline()

    # --- opening summary (sentence -> source-field map) -------------
    summary = []
    filename = payload.get("filename")
    first_seen = payload.get("first_seen")
    last_seen = payload.get("last_seen")
    if filename:
        if first_seen and last_seen:
            summary.append(
                f"File {filename}: recorded from {first_seen} to "
                f"{last_seen}.")
        else:
            summary.append(f"File {filename}.")
    health = payload.get("health")
    if isinstance(health, dict) and health.get("label"):
        summary.append(
            f"Overall, the recorded messages are labelled "
            f"{health['label']}.")
    results = payload.get("results")
    parsed_lines = results.get("parsed_lines") if isinstance(results, dict) else None
    if isinstance(parsed_lines, int):
        total = sum(g.get("count") or 0 for g in groups)
        summary.append(
            f"{parsed_lines} lines were parsed, with {len(groups)} "
            f"issue group(s) and {total} recorded occurrence(s).")
    if lead is not None:
        summary.append(
            f"The investigation lead is \"{lead['template']}\" "
            f"({lead['count']} occurrence(s)).")
    elif lead_template is not None:
        # Dangling diagnostic_issue: no group projection backs the
        # named lead, so no lead is fabricated (A1 positive).
        limitations.append(
            "The free report's investigation lead has no matching "
            "issue group in this report, so no lead is shown.")
    if checks:
        summary.append(f"Start with: {checks[0]['text']}")
    summary.append(BRIEF_NOT_ESTABLISHED)

    _check_deadline()
    return {
        "summary": summary,
        "lead": lead,
        "why_first": why_first,
        "sequence": sequence,
        "priority_checks": checks,
        "limitations": limitations,
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
    if clock() - started > deadline_seconds:
        raise AnalysisError("generation deadline exceeded")
    brief = _build_brief(
        source_payload, groups, coverage, started=started, clock=clock,
        deadline_seconds=deadline_seconds)
    if clock() - started > deadline_seconds:
        raise AnalysisError("generation deadline exceeded")
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
        "brief": brief,
        "groups": groups,
        "elapsed": round(clock() - started, 3),
    }


# ---------------------------------------------------------------------------
# Presentation projections — the ONLY shapes HTML/PDF/CSV/JSON may use.
# Internal refs, digests and provenance internals never cross here.
# ---------------------------------------------------------------------------

def _public_brief(brief):
    """Allowlisted Brief projection (Amendment A1 / P1-1).

    Named fields only, strings only where strings belong: a stored
    brief carrying nested claim dicts, evidence refs or digests
    projects NONE of them. Returns None for a missing/malformed
    brief (every pre-#162 artifact), which renderers treat as "no
    brief section".
    """
    if not isinstance(brief, dict):
        return None

    def _strings(values):
        return [v for v in values or [] if isinstance(v, str)]

    def _counts(values):
        if not isinstance(values, dict):
            return {}
        return {str(k): v for k, v in values.items() if isinstance(v, int)}

    def _excerpt(excerpt):
        if not isinstance(excerpt, dict):
            return None
        return {
            "analysis_line_number": excerpt.get("analysis_line_number"),
            "text": excerpt.get("text") if isinstance(excerpt.get("text"), str) else "",
            "timestamp": excerpt.get("timestamp"),
            "service": excerpt.get("service"),
            "level": excerpt.get("level"),
            "text_truncated": bool(excerpt.get("text_truncated")),
        }

    lead = None
    raw_lead = brief.get("lead")
    if isinstance(raw_lead, dict) and isinstance(raw_lead.get("template"), str):
        lead = {
            "template": raw_lead.get("template"),
            "count": raw_lead.get("count") if isinstance(raw_lead.get("count"), int) else 0,
            "level": raw_lead.get("level") if isinstance(raw_lead.get("level"), str) else "",
            "level_counts": _counts(raw_lead.get("level_counts")),
            "services": _strings(raw_lead.get("services")),
            "first_seen": raw_lead.get("first_seen") if isinstance(raw_lead.get("first_seen"), str) else None,
            "last_seen": raw_lead.get("last_seen") if isinstance(raw_lead.get("last_seen"), str) else None,
            "symptom": raw_lead.get("symptom") if isinstance(raw_lead.get("symptom"), str) else None,
            "cause": raw_lead.get("cause") if isinstance(raw_lead.get("cause"), str) else None,
            "excerpts": [e for e in (_excerpt(x) for x in raw_lead.get("excerpts") or []) if e],
            "limitations": _strings(raw_lead.get("limitations")),
        }
    why_first = None
    raw_why = brief.get("why_first")
    if isinstance(raw_why, dict):
        why_first = {
            "statement": raw_why.get("statement") if isinstance(raw_why.get("statement"), str) else None,
            "facts": raw_why.get("facts") if isinstance(raw_why.get("facts"), str) else None,
            "count": raw_why.get("count") if isinstance(raw_why.get("count"), int) else 0,
            "level": raw_why.get("level") if isinstance(raw_why.get("level"), str) else "",
            "level_counts": _counts(raw_why.get("level_counts")),
            "first_seen": raw_why.get("first_seen") if isinstance(raw_why.get("first_seen"), str) else None,
            "last_seen": raw_why.get("last_seen") if isinstance(raw_why.get("last_seen"), str) else None,
            "limitation": raw_why.get("limitation") if isinstance(raw_why.get("limitation"), str) else None,
        }
    sequence = None
    raw_sequence = brief.get("sequence")
    if isinstance(raw_sequence, dict):
        entries = []
        for entry in raw_sequence.get("entries") or []:
            if isinstance(entry, dict) and isinstance(entry.get("template"), str):
                entries.append({
                    "template": entry.get("template"),
                    "first_seen": entry.get("first_seen") if isinstance(entry.get("first_seen"), str) else None,
                    "last_seen": entry.get("last_seen") if isinstance(entry.get("last_seen"), str) else None,
                })
        sequence = {
            "caption": raw_sequence.get("caption") if isinstance(raw_sequence.get("caption"), str) else None,
            "entries": entries,
        }
    checks = []
    for check in brief.get("priority_checks") or []:
        if isinstance(check, dict) and isinstance(check.get("text"), str):
            checks.append({
                "template": check.get("template") if isinstance(check.get("template"), str) else None,
                "text": check.get("text"),
                "motivation": check.get("motivation") if isinstance(check.get("motivation"), str) else "",
                "support": check.get("support") if isinstance(check.get("support"), str) else "",
                "weaken": check.get("weaken") if isinstance(check.get("weaken"), str) else "",
            })
    return {
        "summary": _strings(brief.get("summary")),
        "lead": lead,
        "why_first": why_first,
        "sequence": sequence,
        "priority_checks": checks,
        "limitations": _strings(brief.get("limitations")),
    }


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
        "brief": _public_brief(artifact.get("brief")),
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


def brief_text_lines(brief) -> list[str]:
    """Plain-text lines for an already-public Brief projection.

    Used by projection_text_lines (the plain-text helper). The PDF
    renderer does NOT use this helper — Amendment A1 / P1-2: it
    renders the Brief directly from public_projection() inside
    generate_deep_dive_pdf().
    """
    if not isinstance(brief, dict):
        return []
    lines = ["Investigation Brief"]
    for sentence in brief.get("summary") or []:
        lines.append(sentence)
    lead = brief.get("lead")
    if lead:
        lines.append("")
        lines.append(f"Investigation lead: {lead.get('template')} "
                     f"x {lead.get('count')}")
        if lead.get("symptom"):
            lines.append(f"Explanation: {lead['symptom']}")
        if lead.get("cause"):
            lines.append(f"What this may mean: {lead['cause']}")
        for excerpt in lead.get("excerpts") or []:
            lines.append(f"Evidence (analysis line "
                         f"{excerpt.get('analysis_line_number')}): "
                         f"{excerpt.get('text')}")
        for limit in lead.get("limitations") or []:
            lines.append(f"Limit: {limit}")
    why = brief.get("why_first")
    if why:
        if why.get("statement"):
            lines.append(why["statement"])
        if why.get("facts"):
            lines.append(why["facts"])
        if why.get("limitation"):
            lines.append(why["limitation"])
    sequence = brief.get("sequence")
    if sequence:
        lines.append("")
        lines.append("Observed sequence")
        if sequence.get("caption"):
            lines.append(sequence["caption"])
        for entry in sequence.get("entries") or []:
            span = entry.get("first_seen") or ""
            if entry.get("last_seen") and entry.get("last_seen") != entry.get("first_seen"):
                span = f"{span} - {entry['last_seen']}"
            lines.append(f"{span}: {entry.get('template')}")
    checks = brief.get("priority_checks") or []
    if checks:
        lines.append("")
        lines.append("Priority checks")
        for check in checks:
            lines.append(f"Check: {check.get('text')}")
            if check.get("motivation"):
                lines.append(f"Motivation: {check['motivation']}")
            if check.get("support"):
                lines.append(check["support"])
            if check.get("weaken"):
                lines.append(check["weaken"])
    for limit in brief.get("limitations") or []:
        lines.append(f"Limit: {limit}")
    return lines


def projection_text_lines(projection) -> list[str]:
    """Plain-language lines for the PDF renderer."""
    lines = [projection.get("summary") or ""]
    brief_lines = brief_text_lines(projection.get("brief"))
    if brief_lines:
        lines.append("")
        lines.extend(brief_lines)
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
