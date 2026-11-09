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
  pagination furniture stripped — narrowly, in furniture form only
  (Codex P2 on PR #175, remediated): the footer lines and their
  page-number chunks; the header timestamp, matched as the exact
  ``Generated: YYYY-MM-DD HH:MM UTC`` string the generator emits
  (pdf_export formats it with that strftime) and normalized in
  place, never a whole-line drop — a body line that merely
  contains ``Generated:`` is content and stays; and ``(continued)``
  page-break labels, which the generator emits either as a line of
  their own or as a suffix on the repeated block label — only
  those two positions are stripped, the word anywhere else in a
  line is content and stays;
- a rendered-content skeleton (Codex P2 on PR #175, remediated):
  for each page content stream, the stream with every ``BT``..``ET``
  text block elided (text is compared via the extracted text above,
  and the header timestamp lives inside a text block), hashed —
  this keeps the drawing and color operators that carry branding
  (the accent header rule, text colors) in the comparison; plus a
  hash of each embedded image's stream data (the branding logo).
  Font and CMap streams are excluded: font subsets legitimately
  vary with the glyphs a generation happens to use. Verified
  empirically: two generations of one report 1.2s apart have
  identical skeletons, while an accent-only change and a
  logo-only change each change the skeleton.

No new dependency: stream parsing and text extraction reuse the
stdlib helpers the #160 suite already maintains
(``test_issue160_designed_reports``); fpdf2 embeds subset TTFs whose
content streams carry glyph IDs, so naive string search over the
raw bytes cannot substitute for extraction.
"""

import hashlib
import re

from app.pdf_export import FOOTER_TEXT
from test_issue160_designed_reports import _streams_by_obj, extract_pdf_text

_PAGE_RE = re.compile(rb"/Type\s*/Page[^s]")
_TITLE_RE = re.compile(rb"/Title \(([^)]*)\)")
# The header timestamp in its exact generated form (pdf_export:
# strftime("%Y-%m-%d %H:%M UTC")). Anything else after "Generated:"
# is report content, not furniture.
_GENERATED_TS_RE = re.compile(r"Generated: \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC")
_CONTINUED_SUFFIX = " (continued)"
_TEXT_BLOCK_RE = re.compile(rb"BT.*?ET", re.DOTALL)


def _page_count(pdf_bytes):
    return len(_PAGE_RE.findall(pdf_bytes))


def _normalized_text(text):
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
        line = _GENERATED_TS_RE.sub("Generated: <timestamp>", line)
        stripped = line.strip()
        if stripped == "(continued)":
            # Bare page-break label line: furniture.
            continue
        if stripped.endswith(_CONTINUED_SUFFIX):
            # Repeated block label: only the suffix is furniture;
            # the label text itself is compared.
            line = stripped[: -len(_CONTINUED_SUFFIX)]
        kept.append(line)
    return re.sub(r"\s+", " ", " ".join(kept)).strip()


def _render_skeleton(pdf_bytes):
    """Deterministic hashes of the non-text rendering, in object
    order: page content streams with text blocks elided (drawing /
    color operators — the accent rule and text colors — remain),
    and embedded image stream data (the branding logo)."""
    parts = []
    streams = _streams_by_obj(pdf_bytes)
    for num in sorted(streams):
        dict_part, stream = streams[num]
        if stream is None:
            continue
        if b"/Subtype /Image" in dict_part:
            parts.append(("image", hashlib.sha256(stream).hexdigest()))
        elif b"BT" in stream:
            skeleton = _TEXT_BLOCK_RE.sub(b"BT <text> ET", stream)
            parts.append(("content", hashlib.sha256(skeleton).hexdigest()))
        # Font-file and CMap streams are not rendered content and
        # their subsets vary with glyph usage: excluded.
    return tuple(parts)


def pdf_content_signature(pdf_bytes):
    """Content-level signature of a generated PDF (see module docstring).

    Two generations of the same report content have equal signatures
    however far apart they were generated; any change to the rendered
    content (body text, header branding/title lines, branding accent
    or logo, page count, footer coverage, document title) changes
    the signature."""
    text = extract_pdf_text(pdf_bytes)
    title = _TITLE_RE.search(pdf_bytes)
    return (
        pdf_bytes[:8],
        title.group(1).decode("latin-1") if title else None,
        _page_count(pdf_bytes),
        text.count(FOOTER_TEXT),
        _normalized_text(text),
        _render_skeleton(pdf_bytes),
    )
