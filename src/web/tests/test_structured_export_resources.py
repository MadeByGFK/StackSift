"""Issue #105 resource-bound tests (spec §8): deadline + size ceiling.

These limits are policy enforced in structured_export.generate_export;
exceeding either raises instead of truncating, and the route's failure
path fully releases the reservation (covered in the e2e suite).
"""

import pytest

from app import structured_export as se


def _payload():
    return {
        "results": {"issues": {"A": {"level": "ERROR", "count": 1, "services": []}}},
        "sorted_issues": [["A", {"level": "ERROR", "count": 1}]],
    }


def test_generate_export_size_ceiling():
    with pytest.raises(se.StructuredExportError):
        se.generate_export(_payload(), "csv", max_bytes=10)


def test_generate_export_deadline():
    ticks = iter([0.0, 999.0])
    with pytest.raises(se.StructuredExportError):
        se.generate_export(_payload(), "json", deadline_seconds=10.0,
                           clock=lambda: next(ticks))


def test_generate_export_within_bounds():
    data = se.generate_export(_payload(), "csv", max_bytes=1024, deadline_seconds=60)
    assert data.startswith(b"template,level,count,services,first_seen,last_seen\r\n")


def test_validate_format_rejects_aliases():
    for bad in ("CSV", "xml", "", "pdf", "json "):
        with pytest.raises(se.StructuredExportError):
            se.validate_format(bad)
    assert se.validate_format("csv") == "csv"
    assert se.validate_format("json") == "json"


def test_safe_download_name_sanitizes():
    name = se.safe_download_name("../../evil name→.log", "abc-123", "csv")
    assert name.endswith(".csv")
    assert "→" not in name and "/" not in name and " " not in name
    fallback = se.safe_download_name("→→→", "abc-123", "json")
    assert fallback == "stacksift-report-report-abc-123.json"


def test_decode_artifact_strict_base64_and_digest():
    import base64, hashlib, json as _json
    from app import credits as C
    payload = _payload()
    data = se.payload_to_csv(payload)
    manifest = {
        "artifact_kind": "structured_export", "schema_version": 1,
        "source_result_id": "src-1", "format": "csv",
        "content_base64": base64.b64encode(data).decode(),
        "content_byte_count": len(data),
        "content_digest": hashlib.sha256(data).hexdigest(),
    }
    out, _ = se.decode_artifact(manifest, expected_format="csv", expected_source_id="src-1")
    assert out == data
    for mutated in (
        dict(manifest, content_base64="!!!not-base64!!!"),
        dict(manifest, content_digest="0" * 64),
        dict(manifest, content_byte_count=len(data) + 1),
        dict(manifest, format="json"),
        dict(manifest, schema_version=99),
    ):
        with pytest.raises(se.StructuredExportError):
            se.decode_artifact(mutated, expected_format="csv", expected_source_id="src-1")
