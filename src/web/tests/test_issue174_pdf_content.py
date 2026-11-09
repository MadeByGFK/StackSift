"""Issue #174 / PR #175 remediation: teeth for pdf_content_signature.

The signature must be generation-invariant (same report generated
seconds apart compares equal) while remaining sensitive to every
kind of content the raw byte-equality assertions it replaced could
see — including the two blind spots Codex's PR #175 review found in
the first version:

- body text that merely CONTAINS the furniture substrings
  (``Generated:`` / ``(continued)``) is content, not furniture;
- non-text branding (the accent color, the logo image) is rendered
  content, even though it never appears in the extracted text.

Generator-level: no routes, no database. Each sensitivity test was
verified to FAIL against the pre-remediation helper and pass with
it (the generation-invariance and plain-body tests pass on both).
"""

import json
import time

from app.pdf_export import generate_report_pdf
from pdf_content import pdf_content_signature


def _manifest(template="failed to connect to db: timeout"):
    return json.dumps({
        "filename": "sample.log",
        "results": {"total_lines": 500, "parsed_lines": 490,
                    "malformed_lines": 10},
        "health": {"label": "Warning", "color": "yellow"},
        "sorted_issues": [[template, {"level": "ERROR", "count": 4}]],
        "first_seen": "2024-01-01 10:00:00",
        "last_seen": "2024-01-01 11:00:00", "elapsed": 1.25,
    })


def _logo(tmp_path, name, rgb):
    from PIL import Image
    path = tmp_path / name
    Image.new("RGB", (80, 20), rgb).save(str(path))
    return {"logo_path": str(path), "logo_width": 80, "logo_height": 20}


def test_same_report_two_generations_equal_signature():
    first = generate_report_pdf(_manifest(), "sample.log")
    time.sleep(1.2)  # cross the /CreationDate one-second boundary
    second = generate_report_pdf(_manifest(), "sample.log")
    assert first != second  # raw bytes DO differ (the #174 flake)
    assert pdf_content_signature(first) == pdf_content_signature(second)


def test_plain_body_change_changes_signature():
    a = generate_report_pdf(_manifest("failed to connect to db: timeout"),
                            "sample.log")
    b = generate_report_pdf(_manifest("failed to connect to cache: timeout"),
                            "sample.log")
    assert pdf_content_signature(a) != pdf_content_signature(b)


def test_generated_substring_in_body_is_content():
    a = generate_report_pdf(_manifest("Generated: 42 errors in the batch"),
                            "sample.log")
    b = generate_report_pdf(_manifest("Generated: 99 errors in the batch"),
                            "sample.log")
    assert pdf_content_signature(a) != pdf_content_signature(b)


def test_continued_substring_in_body_is_content():
    a = generate_report_pdf(
        _manifest("query failed (continued) on replica"), "sample.log")
    b = generate_report_pdf(
        _manifest("query succeeded (continued) on replica"), "sample.log")
    assert pdf_content_signature(a) != pdf_content_signature(b)


def test_accent_only_change_changes_signature():
    plain = generate_report_pdf(_manifest(), "sample.log")
    accented = generate_report_pdf(_manifest(), "sample.log",
                                   branding={"accent": "#ff0000"})
    assert pdf_content_signature(plain) != pdf_content_signature(accented)


def test_logo_only_change_changes_signature(tmp_path):
    red = generate_report_pdf(_manifest(), "sample.log",
                              branding=_logo(tmp_path, "red.png",
                                             (200, 30, 30)))
    blue = generate_report_pdf(_manifest(), "sample.log",
                               branding=_logo(tmp_path, "blue.png",
                                              (30, 30, 220)))
    plain = generate_report_pdf(_manifest(), "sample.log")
    assert pdf_content_signature(red) != pdf_content_signature(blue)
    assert pdf_content_signature(red) != pdf_content_signature(plain)
