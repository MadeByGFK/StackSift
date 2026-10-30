"""Structured export serializers for stored analysis payloads."""

from __future__ import annotations

import csv
import io
import json


class StructuredExportError(ValueError):
    """Raised when a stored payload cannot be serialized safely."""


def _require_payload_dict(payload):
    if not isinstance(payload, dict):
        raise StructuredExportError("payload must be a dict")


def _require_results_issues(payload):
    results = payload.get("results")
    if not isinstance(results, dict):
        raise StructuredExportError("payload.results must be a dict")
    issues = results.get("issues")
    if not isinstance(issues, dict):
        raise StructuredExportError("payload.results.issues must be a dict")
    return issues


def _validate_template(template):
    if not isinstance(template, str) or template == "":
        raise StructuredExportError("invalid issue template")


def _validate_level(level):
    if not isinstance(level, str) or level == "":
        raise StructuredExportError("invalid issue level")


def _validate_count(count):
    if isinstance(count, bool) or not isinstance(count, int):
        raise StructuredExportError("invalid issue count")


def _services_cell(group):
    if "services" not in group:
        return ""
    services = group.get("services")
    if not isinstance(services, list):
        raise StructuredExportError("invalid issue services")
    return json.dumps(services, ensure_ascii=False, separators=(",", ":"))


def _timestamp_cell(group, key):
    value = group.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise StructuredExportError(f"invalid {key}")
    return value


def _normalize_sorted_entry(entry):
    if not isinstance(entry, (list, tuple)) or len(entry) != 2:
        raise StructuredExportError("invalid sorted_issues entry")
    template, group = entry
    if not isinstance(group, dict):
        raise StructuredExportError("invalid sorted_issues group")
    return template, group


def _ordered_issue_rows(payload, issues):
    sorted_issues = payload.get("sorted_issues")
    if sorted_issues is None:
        return [(template, issues[template]) for template in sorted(issues)]

    if not isinstance(sorted_issues, list):
        raise StructuredExportError("payload.sorted_issues must be a list")

    ordered = []
    seen = set()
    for entry in sorted_issues:
        template, sorted_group = _normalize_sorted_entry(entry)
        _validate_template(template)
        if template in seen:
            raise StructuredExportError("duplicate template in sorted_issues")
        seen.add(template)

        issue_group = issues.get(template)
        if issue_group is None or not isinstance(issue_group, dict):
            raise StructuredExportError("sorted_issues references missing issue group")

        sorted_level = sorted_group.get("level")
        sorted_count = sorted_group.get("count")
        issue_level = issue_group.get("level")
        issue_count = issue_group.get("count")
        _validate_level(sorted_level)
        _validate_level(issue_level)
        _validate_count(sorted_count)
        _validate_count(issue_count)
        if sorted_level != issue_level or sorted_count != issue_count:
            raise StructuredExportError("sorted_issues contradicts results.issues")

        ordered.append((template, issue_group))

    if seen != set(issues):
        raise StructuredExportError("sorted_issues does not match results.issues templates")

    return ordered


def payload_to_csv(payload) -> bytes:
    """Serialize a stored payload to UTF-8 CSV bytes."""
    _require_payload_dict(payload)
    issues = _require_results_issues(payload)
    ordered_rows = _ordered_issue_rows(payload, issues)

    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=",", lineterminator="\r\n")
    writer.writerow(["template", "level", "count", "services", "first_seen", "last_seen"])

    for template, group in ordered_rows:
        _validate_template(template)
        if not isinstance(group, dict):
            raise StructuredExportError("invalid issue group")
        level = group.get("level")
        count = group.get("count")
        _validate_level(level)
        _validate_count(count)
        writer.writerow(
            [
                template,
                level,
                count,
                _services_cell(group),
                _timestamp_cell(group, "first_seen"),
                _timestamp_cell(group, "last_seen"),
            ]
        )

    return output.getvalue().encode("utf-8")


def payload_to_json(payload) -> bytes:
    """Serialize a stored payload to UTF-8 JSON bytes with trailing newline."""
    _require_payload_dict(payload)
    try:
        text = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise StructuredExportError(str(exc)) from exc

    rendered = f"{text}\n"

    try:
        parsed = json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise StructuredExportError("failed to re-parse exported json") from exc

    if parsed != payload:
        raise StructuredExportError("payload is not JSON-round-trippable")

    return rendered.encode("utf-8")
