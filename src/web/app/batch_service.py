"""Batch analysis (issue #103) — pure combined-report assembly.

Turns the ordered per-file ``analyze_upload()`` payloads into the ONE
stored batch payload (approved spec §5). No HTTP, database, or ledger
concerns live here.

Rules:
- ``combined_issues`` merges by the EXACT normalized template string
  (the ``results["issues"]`` dict key, produced by the analyzer's
  ``normalize_issue()``), summing counts and preserving per-file
  attribution (ordinal + filename + that file's count and the group's
  first-observed level for that file — no invented severity
  distribution, and no cross-file causal/health verdict).
- Per-file sections stay intact: each file's own payload (health,
  diagnostic, incident section, timeline, complexity notices) is
  carried through unchanged under ``files``.
- Summary counts are sums of the per-file analyzer counts; first/last
  seen are min/max over the non-empty per-file values.

B4 budget derivation (re-derived at build time from staging head
5692f65b / base be92e45, post-#104): the pending-store aggregate budget
is ``_PAID_PENDING_BUDGET = 256 MiB`` (issue #104 trim T2 raised it from
64 MiB to hold a 100 MiB oversize input). A batch holds at most
``MAX_BATCH_FILES = 5`` files, each at most the FREE 10 MiB ceiling
(trim B9), so the worst-case original bundle is 5 x 10 MiB = 50 MiB.
The bundle envelope adds a JSON header line (filenames + per-file
server-measured byte/line counts; well under 1 KiB for five files).
Redaction can expand content, but the store accounts for the ACTUAL
redacted envelope size against the 256 MiB aggregate budget and fails
closed at 503, so the nominal bundle uses under 20% of the budget and
leaves over 200 MiB of headroom for other pending uploads. The 51 MiB
pre-multipart guard (50 MiB of file data + 1 MiB of multipart/form
overhead) is therefore consistent with both caps. MAX_BATCH_FILES = 5
stands as approved; its justification is restated here against the
current 256 MiB ceiling rather than the draft's 64 MiB figure.
"""

from __future__ import annotations

SCHEMA_VERSION = 1
MAX_BATCH_FILES = 5
MIN_BATCH_FILES = 2


def batch_severity(level_counts: dict) -> str:
    """History severity from the SUMMED observed level counts.

    Batch-specific extension of credits.outcome_severity(): the batch
    payload has no single ``results`` object, so severity is classified
    from the aggregate level counts instead of fabricating one.
    """
    from app import credits as C
    return C.outcome_severity({"level_counts": dict(level_counts or {})})


def build_batch_payload(per_file: list, pricing: dict) -> dict:
    """Assemble the combined payload.

    ``per_file`` is a list of (ordinal, filename, analyze_upload payload)
    in upload order. ``pricing`` is the server quote snapshot
    {file_count, first_file_cost, additional_file_cost, total_cost}.
    """
    level_counts: dict[str, int] = {}
    service_counts: dict[str, int] = {}
    total_lines = parsed_lines = malformed_lines = 0
    first_seen = last_seen = None
    elapsed = 0.0
    combined: dict[str, dict] = {}
    files = []

    for ordinal, filename, payload in per_file:
        results = payload.get("results") or {}
        total_lines += int(results.get("total_lines") or 0)
        parsed_lines += int(results.get("parsed_lines") or 0)
        malformed_lines += int(results.get("malformed_lines") or 0)
        for level, count in (results.get("level_counts") or {}).items():
            level_counts[level] = level_counts.get(level, 0) + int(count or 0)
        for service, count in (results.get("service_counts") or {}).items():
            service_counts[service] = service_counts.get(service, 0) + int(count or 0)
        fs, ls = results.get("first_seen"), results.get("last_seen")
        if fs:
            first_seen = fs if first_seen is None else min(first_seen, fs)
        if ls:
            last_seen = ls if last_seen is None else max(last_seen, ls)
        elapsed += float(payload.get("elapsed") or 0)
        for template, group in (results.get("issues") or {}).items():
            group = group or {}
            entry = combined.setdefault(
                template, {"template": template, "count": 0, "files": []})
            entry["count"] += int(group.get("count") or 0)
            entry["files"].append({
                "ordinal": ordinal,
                "filename": filename,
                "count": int(group.get("count") or 0),
                "level": group.get("level"),
            })
        files.append({"ordinal": ordinal, "filename": filename, "report": payload})

    combined_issues = sorted(
        combined.values(), key=lambda e: (-e["count"], e["template"]))

    error_count = sum(int(level_counts.get(k, 0)) for k in ("ERROR",))
    critical_count = int(level_counts.get("CRITICAL", 0))
    summary_sentence = (
        f"Across these {len(files)} files, {error_count} ERROR entries and "
        f"{critical_count} CRITICAL entries were observed."
    )
    return {
        "report_kind": "batch",
        "schema_version": SCHEMA_VERSION,
        "filename": f"Batch \u2014 {len(files)} files",
        "elapsed": elapsed,
        "pricing": dict(pricing),
        "summary": {
            "file_count": len(files),
            "total_lines": total_lines,
            "parsed_lines": parsed_lines,
            "malformed_lines": malformed_lines,
            "level_counts": level_counts,
            "service_counts": service_counts,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "unique_issue_patterns": len(combined_issues),
        },
        "summary_sentence": summary_sentence,
        "level_counts": level_counts,
        "combined_issues": combined_issues,
        "files": files,
    }
