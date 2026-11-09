"""Issue #174: content-level comparison for generated PDFs.

Two independently generated PDFs of the SAME report are never
byte-identical in general: fpdf2 embeds a per-generation
``/CreationDate`` (second resolution) in the document info dict and
derives the trailer ``/ID`` from it, so the raw bytes differ whenever
the two generations cross a one-second boundary (verified empirically:
same manifest generated 1.2s apart -> different SHA-256, different
/CreationDate and /ID, identical extracted text). The designed
header's ``Generated:`` line additionally differs across a one-minute
boundary. Byte-equality assertions between two generations therefore
flake — on the slower PostgreSQL CI legs first (issue #174: two CI
runs on an identical tree each failed a different member).

Tests must compare generated PDFs at the content level instead.
``pdf_content_signature`` is that oracle. Its tuple is:

- the PDF header (``%PDF-x.y`` magic/version bytes);
- the document ``/Title`` metadata;
- the page count (structural);
- the designed-footer occurrence count in the extracted text (the
  footer invariant the #160/#163 suites assert directly is one
  footer per page, so signature equality preserves it for both
  sides);
- the extracted text, whitespace-normalized, with generation and
  pagination furniture stripped: the footer lines and their
  page-number chunks, the ``Generated:`` timestamp line, and
  ``(continued)`` page-break labels (the same furniture set the
  #163 suite's ``_normalized_body`` oracle strips, for the same
  reasons). Every other line — including the ``File:`` header line
  and all body content — is compared exactly.

No new dependency: text extraction reuses the stdlib ToUnicode-aware
extractor the #160 suite already maintains
(``test_issue160_designed_reports.extract_pdf_text``); fpdf2 embeds
subset TTFs whose content streams carry glyph IDs, so naive string
search over the raw bytes cannot substitute for it.
"""

import re

from app.pdf_export import FOOTER_TEXT
from test_issue160_designed_reports import extract_pdf_text

_PAGE_RE = re.compile(rb"/Type\s*/Page[^s]")
_TITLE_RE = re.compile(rb"/Title \(([^)]*)\)")


def _page_count(pdf_bytes):
    return len(_PAGE_RE.findall(pdf_bytes))


def pdf_content_signature(pdf_bytes):
    """Content-level signature of a generated PDF (see module docstring).

    Two generations of the same report content have equal signatures
    however far apart they were generated; any change to the rendered
    content (body text, header branding/title lines, page count,
    footer coverage, document title) changes the signature."""
    text = extract_pdf_text(pdf_bytes)
    kept = []
    prev_was_footer = False
    for line in text.splitlines():
        if FOOTER_TEXT in line:
            prev_was_footer = True
            continue
        if prev_was_footer and line.strip().isdigit():
            # The footer's total-page count extracts as its own line.
            prev_was_footer = False
            continue
        prev_was_footer = False
        if "Generated:" in line:
            continue
        # Pagination furniture: a block split across a page break
        # resumes under a "(continued)" label; where the break falls
        # is furniture, not body content (same ruling as #163's
        # _normalized_body oracle).
        if "(continued)" in line:
            continue
        kept.append(line)
    normalized = re.sub(r"\s+", " ", " ".join(kept)).strip()
    title = _TITLE_RE.search(pdf_bytes)
    return (
        pdf_bytes[:8],
        title.group(1).decode("latin-1") if title else None,
        _page_count(pdf_bytes),
        text.count(FOOTER_TEXT),
        normalized,
    )
