"""Structured export serializers for stored analysis payloads.

Issue #105: CSV (six-column issue-group table) and JSON (full validated
stored payload) generation from an already-validated source snapshot,
plus the artifact-side helpers the routes use: format validation,
report-kind gating, safe download names, bounded generation and strict
artifact decoding/replay validation.
"""

from __future__ import annotations

import base64
import binascii
import csv
import io
import json
import time

EXPORT_FORMATS = ("csv", "json")
SCHEMA_VERSION = 1
MEDIA_TYPES = {
    "csv": "text/csv; charset=utf-8",
    "json": "application/json; charset=utf-8",
}
# Spec §8 resource bounds (adjustable policy, enforced before settlement):
# generation must stay bounded; exceeding either limit fails the export
# and the caller fully releases the reservation — never truncates.
MAX_EXPORT_BYTES = 64 * 1024 * 1024
GENERATION_DEADLINE_SECONDS = 10.0


class StructuredExportError(ValueError):
    """Raised when a stored payload cannot be serialized safely."""


class UnsupportedReportKind(StructuredExportError):
    """Raised for compare/batch/unknown report_kind discriminators (§7)."""


def validate_format(export_format):
    """Return the canonical format or raise for anything but csv/json."""
    if export_format not in EXPORT_FORMATS:
        raise StructuredExportError(f"unsupported export format: {export_format!r}")
    return export_format


def check_report_kind(payload):
    """Fail closed (§7) on compare/batch/unknown discriminators.

    Existing single-file manifests carry no ``report_kind``; an explicit
    ``single``/``analysis`` discriminator is the verified single-file
    shape. Anything else is deferred, before any charge.
    """
    _require_payload_dict(payload)
    kind = payload.get("report_kind")
    if kind is None or kind in ("single", "analysis"):
        return
    raise UnsupportedReportKind(
        "Structured export is not yet supported for this report type"
    )


def safe_download_name(source_filename, source_result_id, export_format):
    """Attachment filename derived from a sanitized basename/source id.

    Never interpolates a raw stored filename into a header: only
    [A-Za-z0-9._-] survive, mirroring main._safe_download_filename.
    """
    base = str(source_filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    safe = "".join(
        ch if (ch.isascii() and (ch.isalnum() or ch in "._-")) else "-"
        for ch in stem
    ).strip("-.")
    if not safe:
        safe = f"report-{source_result_id}"
    return f"stacksift-report-{safe}.{export_format}"


def generate_export(payload, export_format, *, deadline_seconds=GENERATION_DEADLINE_SECONDS,
                    max_bytes=MAX_EXPORT_BYTES, clock=time.monotonic):
    """Generate export bytes from a validated snapshot, bounded (§8)."""
    validate_format(export_format)
    check_report_kind(payload)
    started = clock()
    if export_format == "csv":
        data = payload_to_csv(payload)
    else:
        data = payload_to_json(payload)
    if len(data) > max_bytes:
        raise StructuredExportError("export exceeds maximum size")
    if clock() - started > deadline_seconds:
        raise StructuredExportError("export generation exceeded deadline")
    return data


def decode_artifact(manifest, *, expected_format=None, expected_source_id=None):
    """Validate a stored structured-export artifact manifest and return
    (export_bytes, manifest). Strict base64, byte-count and digest are
    all verified; any mismatch raises StructuredExportError so replay /
    download fails closed instead of serving corrupt bytes.
    """
    import hashlib

    if not isinstance(manifest, dict):
        raise StructuredExportError("invalid artifact manifest")
    if manifest.get("artifact_kind") != "structured_export":
        raise StructuredExportError("not a structured export artifact")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise StructuredExportError("unsupported artifact schema version")
    fmt = manifest.get("format")
    validate_format(fmt)
    if expected_format is not None and fmt != expected_format:
        raise StructuredExportError("artifact format mismatch")
    if expected_source_id is not None and manifest.get("source_result_id") != str(expected_source_id):
        raise StructuredExportError("artifact source mismatch")
    encoded = manifest.get("content_base64")
    if not isinstance(encoded, str):
        raise StructuredExportError("artifact content missing")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StructuredExportError("artifact content is not valid base64") from exc
    if manifest.get("content_byte_count") != len(data):
        raise StructuredExportError("artifact content byte count mismatch")
    if manifest.get("content_digest") != hashlib.sha256(data).hexdigest():
        raise StructuredExportError("artifact content digest mismatch")
    return data, manifest


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
