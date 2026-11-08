"""PDF export for StackSift analysis reports (Phase 2B).

Generates a PDF from a stored analysis result's storage_manifest JSON.
The PDF mirrors the on-screen report: summary, statistics, investigate-first
diagnostic, incident section, notable events, timeline, and all issues.
Uses fpdf2 (pure Python, no system dependencies).

Issue #160: the standard report PDF and the Analysis Report PDF share ONE
design layer (class ``_DesignedPDF`` + the helpers below): identical
header/footer, brand tokens single-sourced in ``BRAND``, vendored brand
fonts (DM Sans / IBM Plex Mono) with a hard Helvetica fallback, and
left-aligned body text throughout — no justified "word soup". The
batch/comparison generators below keep their original code paths.
Presentation only: no content, engine, pricing or credit behavior here.
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import MethodReturnValue

# Preferred: the manifest already carries the health color token
# (determine_health returns red/yellow/green/gray). Label mapping is a
# fallback for legacy manifests that only have a label.
HEALTH_COLORS = {
    "red": (185, 28, 28),
    "yellow": (217, 119, 6),
    "green": (22, 163, 74),
    "gray": (100, 100, 100),
}
HEALTH_LABEL_COLORS = {
    "Critical": (185, 28, 28),
    "Warning": (217, 119, 6),
    "Healthy": (22, 163, 74),
    "Elevated Incident Activity": (185, 28, 28),
    "Increased Error Activity": (217, 119, 6),
    "No Escalation Detected": (22, 163, 74),
    "No Significant Issues Detected": (22, 163, 74),
}

# Issue #160 decision 2, amended by A1 P2-4: brand tokens are IMMUTABLE
# defaults, resolved PER RENDER by resolve_tokens() into a frozen
# ResolvedTokens object that is passed through the helpers. This dict is
# never mutated at runtime (no cross-request contamination), and the
# token names/values are the same ones the web surface defines as CSS
# :root variables in app/static/style.css (--accent, --navy,
# --severity-critical/-warning/-info, --font-body, --font-code) — the
# web/PDF agreement is asserted by test.
#
# Brand-overridable (via the #163 `branding` argument): ONLY the accent
# color, plus the header business text / client name / report title /
# logo zone. Fixed forever (integrity rule): severity, limitation and
# redaction colors are NEVER brand-overridable.
BRAND = {
    "navy": (30, 42, 74),            # web --navy: #1e2a4a
    "gold": (212, 175, 55),          # web --accent: #d4af37
    "ink": (26, 32, 44),
    "muted": (100, 100, 100),
    "panel": (238, 241, 246),
    "border": (203, 213, 225),
    "severity": {
        "CRITICAL": HEALTH_COLORS["red"],      # web --severity-critical
        "ERROR": HEALTH_COLORS["red"],
        "WARN": HEALTH_COLORS["yellow"],       # web --severity-warning
        "WARNING": HEALTH_COLORS["yellow"],
        "INFO": HEALTH_COLORS["gray"],         # web --severity-info
    },
    "limitation": (100, 100, 100),
    "redaction": HEALTH_COLORS["red"],
}

NAVY = BRAND["navy"]
GRAY = BRAND["muted"]
BLACK = BRAND["ink"]

#: The only BRAND token a branding dict may override.
BRAND_OVERRIDABLE = frozenset({"accent"})
#: Tokens a branding dict can never change (contrast/integrity rule).
BRAND_FIXED = frozenset(
    {"navy", "gold", "ink", "muted", "panel", "border",
     "severity", "limitation", "redaction"})


def _parse_color(value):
    """Parse a branding color: '#rrggbb' or an (r, g, b) triple."""
    if isinstance(value, (tuple, list)) and len(value) == 3:
        try:
            rgb = tuple(int(c) for c in value)
        except (TypeError, ValueError):
            return None
        return rgb if all(0 <= c <= 255 for c in rgb) else None
    if isinstance(value, str) and len(value) == 7 and value.startswith("#"):
        try:
            return tuple(int(value[i:i + 2], 16) for i in (1, 3, 5))
        except ValueError:
            return None
    return None


@dataclass(frozen=True)
class ResolvedTokens:
    """Per-render brand tokens (A1 P2-4). Built fresh by
    resolve_tokens() for every render and threaded through the design
    helpers; nothing here is shared or mutated across renders."""
    navy: tuple
    gold: tuple
    accent: tuple
    ink: tuple
    muted: tuple
    panel: tuple
    border: tuple
    severity: dict
    limitation: tuple
    redaction: tuple
    business_name: str | None = None
    client_name: str | None = None
    report_title: str | None = None
    logo_path: str | None = None
    # Issue #163 (A6): stored pixel dimensions for contain-fit scaling.
    logo_width: int | None = None
    logo_height: int | None = None


def resolve_tokens(branding=None) -> ResolvedTokens:
    """Resolve the tokens for ONE render from the immutable BRAND
    defaults plus an optional #163 branding dict.

    Only `accent` may be overridden (see BRAND_OVERRIDABLE); any
    severity/limitation/redaction keys in the branding dict are
    deliberately ignored — those colors are fixed by the integrity
    rule in BRAND_FIXED.
    """
    b = branding or {}
    accent = _parse_color(b.get("accent")) or BRAND["gold"]
    return ResolvedTokens(
        navy=BRAND["navy"], gold=BRAND["gold"], accent=accent,
        ink=BRAND["ink"], muted=BRAND["muted"], panel=BRAND["panel"],
        border=BRAND["border"], severity=dict(BRAND["severity"]),
        limitation=BRAND["limitation"], redaction=BRAND["redaction"],
        business_name=b.get("business_name") or None,
        client_name=b.get("client_name") or None,
        report_title=b.get("report_title") or None,
        logo_path=b.get("logo_path") or None,
        logo_width=b.get("logo_width") or None,
        logo_height=b.get("logo_height") or None,
    )


def _health_color(health: dict) -> tuple:
    return (
        HEALTH_COLORS.get((health.get("color") or "").lower())
        or HEALTH_LABEL_COLORS.get(health.get("label", ""))
        or BLACK
    )
MAX_ISSUES = 100


_PUNCT_MAP = {
    "“": '"', "”": '"', "‘": "'", "’": "'",
    "–": "-", "—": "-", "•": "-", "…": "...",
}


def _s(text) -> str:
    """Coerce to str and make it safe for fpdf2 core fonts (latin-1 only).

    Common cp1252 punctuation is mapped to ASCII equivalents first;
    anything still outside latin-1 is replaced. Used ONLY on the
    Helvetica fallback path (issue #160 decision 3): when the vendored
    brand fonts load, text renders as full Unicode.
    """
    text = str(text)
    for src, dst in _PUNCT_MAP.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", "replace").decode("latin-1")


# ---------------------------------------------------------------------------
# Issue #160: shared design layer for the standard + Analysis Report PDFs.
# ---------------------------------------------------------------------------

_FONT_DIR = Path(__file__).resolve().parent / "assets" / "fonts"
_FONT_FILES = {
    ("DMSans", ""): "DMSans-Regular.ttf",
    ("DMSans", "B"): "DMSans-Bold.ttf",
    ("DMSans", "I"): "DMSans-Italic.ttf",
    ("IBMPlexMono", ""): "IBMPlexMono-Regular.ttf",
}
# A1 P3-6: exact pinned font files. Provenance (source URLs, licenses)
# lives in assets/fonts/FONTS.md + the per-family OFL notices alongside
# the binaries; a file whose bytes do not match its recorded hash is
# treated as corrupt and triggers the disclosed Helvetica fallback.
FONT_SHA256 = {
    "DMSans-Regular.ttf":
        "b0ae3e89a7d3ef2b1838bb4b1ceb0b17cc3435af061eee809d76aa623ff116e9",
    "DMSans-Bold.ttf":
        "2a8e7f713ee79fbccdef3cef5c787aff47580299f7da60144961e7db2ec08211",
    "DMSans-Italic.ttf":
        "cb30796ef338a70498e301f2c333f00d4fc23bacfa267be09673fdac43356a96",
    "IBMPlexMono-Regular.ttf":
        "a7fdc993f9f0387caedba4e42521136fa97e4c0837ae6239bf0413ccf8af00c2",
}
BODY_FONT = "DMSans"
MONO_FONT = "IBMPlexMono"
FOOTER_TEXT = "Generated by StackSift (stacksift.goodfolkdigital.com)"
#: A1 P1-1(c): the degraded Helvetica mode is DISCLOSED on page 1.
FALLBACK_NOTICE = (
    "Notice: rendered in fallback font (Helvetica) because the brand "
    "fonts could not be loaded. Some characters may be replaced in "
    "this degraded rendering.")
#: A1 P1-1(b): a glyph the rendering font cannot draw is shown as this
#: explicit visible token — never a silent '?', never dropped.
UNSUPPORTED_TEMPLATE = "[unsupported character U+{cp:04X}]"


def _register_fonts(pdf):
    """Register the vendored brand fonts and probe their coverage.

    Returns {family: frozenset(codepoints)} on success, None when any
    font file is missing, corrupt (SHA-256 mismatch) or unloadable —
    the caller then renders in the disclosed Helvetica fallback mode
    (A1 P1-1c). Paths resolve relative to this module, never the CWD,
    and nothing is ever downloaded at runtime (A1 P3-6).
    """
    try:
        for (family, style), fname in _FONT_FILES.items():
            path = _FONT_DIR / fname
            if not path.is_file():
                return None
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != FONT_SHA256[fname]:
                return None
            pdf.add_font(family, style, str(path))
        coverage = {}
        for family in (BODY_FONT, MONO_FONT):
            cps = set()
            for key, font in pdf.fonts.items():
                if key.lower().startswith(family.lower()):
                    cps.update(font.cw.keys())
            if not cps:
                return None
            coverage[family] = frozenset(cps)
        return coverage
    except Exception:
        return None


def effective_accent(branding=None) -> tuple:
    """Accent color for a render (helper-level #163 seam)."""
    return resolve_tokens(branding).accent


class _DesignedPDF(FPDF):
    """Shared designed-PDF renderer (an FPDF subclass).

    Both in-scope generators build one of these so header, footer,
    headings, body text, evidence blocks and severity chips are drawn
    by exactly the same code — the two PDFs read as siblings. The
    footer is a true per-page footer (FPDF ``footer()`` hook), so it
    appears on EVERY page however pagination falls.
    """

    def __init__(self, *, title, filename, branding=None):
        super().__init__()
        self.title = title
        self.filename = filename
        self.branding = branding or None
        # A1 P2-4: tokens resolved per render, never global mutation.
        self.tokens = resolve_tokens(branding)
        self.generated = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC")
        self._coverage = _register_fonts(self)
        self.fonts_ok = self._coverage is not None
        self.body = BODY_FONT if self.fonts_ok else "Helvetica"
        self.mono = MONO_FONT if self.fonts_ok else "Courier"
        self.alias_nb_pages()
        self.set_auto_page_break(auto=True, margin=22)

    # -- text/font plumbing -------------------------------------------------
    def _t(self, text, *, mono=False) -> str:
        """Make text safe for the CURRENT rendering path (A1 P1-1).

        Brand-font path: the text NEVER passes through _s()'s latin-1
        replacement. A character the target font cannot render becomes
        the explicit visible token [unsupported character U+XXXX].
        Fallback path: the lossy _s() coercion, disclosed on page 1 by
        FALLBACK_NOTICE.
        """
        text = str(text)
        if not self.fonts_ok:
            return _s(text)
        coverage = self._coverage[MONO_FONT if mono else BODY_FONT]
        out = []
        for ch in text:
            if ch == "\n":
                out.append(ch)
            elif ch == "\t":
                out.append(" ")
            elif ord(ch) in coverage:
                out.append(ch)
            else:
                out.append(UNSUPPORTED_TEMPLATE.format(cp=ord(ch)))
        return "".join(out)

    def font(self, style="", size=10, *, mono=False):
        """Set the current font via the design layer (never call
        FPDF.set_font directly in the designed generators). The brand
        set registers real Regular/Bold/Italic faces, so style="I"
        renders in the real DM Sans Italic — it is never stripped,
        synthesized, or remapped (A1 P2-2)."""
        family = self.mono if mono else self.body
        FPDF.set_font(self, family, style, size)

    # -- page furniture ------------------------------------------------------
    def header_block(self):
        """Designed header: branding-ready logo zone (empty when
        unbranded — no placeholder), title, source file, timestamp,
        accent rule. Called once per document, at the top of page 1.
        Every content string wraps via multi_cell (A1 P2-3): nothing
        here can be clipped by a single-line cell()."""
        pdf = self
        tok = self.tokens
        if tok.logo_path:
            # Issue #163 (A6): contain-fit inside max 40mm x 10mm,
            # aspect preserved, dimensions computed from the stored
            # pixel dimensions (or the image file itself). A render
            # failure never fails the export — the business-name text
            # still renders — but it is logged as a warning containing
            # no branding text or bytes.
            try:
                if Path(str(tok.logo_path)).is_file():
                    px_w, px_h = tok.logo_width, tok.logo_height
                    if not px_w or not px_h:
                        from PIL import Image as _PILImage
                        with _PILImage.open(str(tok.logo_path)) as _im:
                            px_w, px_h = _im.size
                    if px_w and px_h:
                        scale = min(40.0 / px_w, 10.0 / px_h)
                        img_w, img_h = px_w * scale, px_h * scale
                    else:
                        img_w, img_h = None, 10.0
                    if img_w:
                        pdf.image(str(tok.logo_path), x=pdf.l_margin,
                                  y=pdf.get_y(), w=img_w, h=img_h)
                    else:
                        pdf.image(str(tok.logo_path), x=pdf.l_margin,
                                  y=pdf.get_y(), h=img_h)
                    pdf.ln(img_h + 2)
            except Exception:
                logging.getLogger(__name__).warning(
                    "Branding logo could not be rendered; export "
                    "continues without the logo image.")
        if tok.business_name:
            self.font("B", 9)
            pdf.set_text_color(*tok.accent)
            pdf.multi_cell(0, 5, self._t(tok.business_name), align="L",
                           new_x="LMARGIN", new_y="NEXT")
        title = tok.report_title or self.title
        self.font("B", 19)
        pdf.set_text_color(*tok.navy)
        pdf.multi_cell(0, 9, self._t(title), align="L",
                       new_x="LMARGIN", new_y="NEXT")
        if tok.client_name:
            self.font("", 10)
            pdf.set_text_color(*tok.muted)
            pdf.multi_cell(0, 6, self._t(f"Prepared for: {tok.client_name}"),
                           align="L", new_x="LMARGIN", new_y="NEXT")
        self.font("", 9, mono=True)
        pdf.set_text_color(*tok.muted)
        pdf.multi_cell(0, 6, self._t(f"File: {self.filename}", mono=True),
                       align="L", new_x="LMARGIN", new_y="NEXT")
        self.font("", 9)
        pdf.multi_cell(0, 6, self._t(f"Generated: {self.generated}"),
                       align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*tok.ink)
        y = pdf.get_y() + 1.5
        pdf.set_draw_color(*tok.accent)
        pdf.set_line_width(0.6)
        pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
        pdf.set_y(y + 3)
        if not self.fonts_ok:
            # A1 P1-1(c): degraded mode is disclosed on the artifact.
            self.font("I", 9)
            pdf.set_text_color(*tok.redaction)
            pdf.multi_cell(0, 5.5, self._t(FALLBACK_NOTICE), align="L",
                           new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*tok.ink)
            pdf.ln(1)

    def footer(self):
        """Designed per-page footer (FPDF hook): the identical string
        on every page of both generators, with page numbering."""
        self.set_y(-16)
        self.font("", 8)
        self.set_text_color(*self.tokens.muted)
        self.cell(0, 8, self._t(
            f"{FOOTER_TEXT} - Page {self.page_no()} of {{nb}}"),
            new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_text_color(*self.tokens.ink)

    # -- content primitives (all body text explicitly left-aligned) ---------
    def section_heading(self, text):
        pdf = self
        pdf.ln(4)
        self.font("B", 13)
        pdf.set_text_color(*self.tokens.navy)
        pdf.multi_cell(0, 7.5, self._t(text), align="L",
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*self.tokens.ink)
        pdf.ln(1)

    def subhead(self, text):
        pdf = self
        pdf.ln(2)
        self.font("B", 10.5)
        pdf.set_text_color(*self.tokens.navy)
        pdf.multi_cell(0, 6, self._t(text), align="L",
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*self.tokens.ink)

    def para(self, text, size=10, style="", color=None):
        pdf = self
        self.font(style, size)
        pdf.set_text_color(*(color or self.tokens.ink))
        pdf.multi_cell(0, 5.8, self._t(text), align="L",
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*self.tokens.ink)
        pdf.ln(1)

    def text_line(self, text, size=11, style="", height=7, color=None):
        """A 'line' of content — rendered with multi_cell, not cell(),
        so long content strings wrap instead of clipping (A1 P2-3)."""
        pdf = self
        self.font(style, size)
        pdf.set_text_color(*(color or self.tokens.ink))
        pdf.multi_cell(0, height, self._t(text), align="L",
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*self.tokens.ink)

    def summary_panel(self, text):
        """The report summary as a distinct filled panel (decision 5a)."""
        pdf = self
        self.font("", 10.5)
        pdf.set_text_color(*self.tokens.ink)
        pdf.set_fill_color(*self.tokens.panel)
        pdf.multi_cell(0, 6.2, self._t(text), align="L", fill=True,
                       new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    def _split_lines(self, text, width, line_h):
        """Split text into rendered lines at the CURRENT font/width
        (fpdf dry run — draws nothing). Long unbroken strings are
        character-split by fpdf's wrap logic: nothing is lost."""
        return self.multi_cell(
            width, line_h, text, align="L", dry_run=True,
            output=MethodReturnValue.LINES)

    def _flow_lines(self, lines, line_h, font_spec, color, *,
                    indent=0, fill=False, rule_color=None,
                    continued_label=None):
        """Render pre-split lines with manual pagination (A1 P2-3).

        Unlike a bare multi_cell, this keeps the visual furniture
        intact across page breaks: the rule is drawn per page segment,
        the footer hook fires on every added page, and a split block
        resumes under `continued_label` on the next page. Lossless:
        every input line is rendered exactly once.
        """
        pdf = self
        style, size, mono = font_spec
        width = pdf.w - pdf.l_margin - pdf.r_margin - indent
        i = 0
        first_chunk = True
        while i < len(lines):
            self.font(style, size, mono=mono)
            pdf.set_text_color(*color)
            if fill:
                pdf.set_fill_color(*self.tokens.panel)
            if not first_chunk and continued_label:
                self.font("", 7.5, mono=True)
                pdf.set_text_color(*self.tokens.muted)
                pdf.set_x(pdf.l_margin + indent)
                pdf.multi_cell(width, 4.5,
                               self._t(continued_label, mono=True),
                               align="L", new_x="LMARGIN", new_y="NEXT")
                self.font(style, size, mono=mono)
                pdf.set_text_color(*color)
                if fill:
                    pdf.set_fill_color(*self.tokens.panel)
            avail = pdf.h - pdf.b_margin - pdf.get_y()
            n = int(avail // line_h)
            if n <= 0:
                pdf.add_page()
                continue
            chunk = lines[i:i + n]
            i += len(chunk)
            y0 = pdf.get_y()
            for line in chunk:
                pdf.set_x(pdf.l_margin + indent)
                pdf.multi_cell(width, line_h, line, align="L", fill=fill,
                               new_x="LMARGIN", new_y="NEXT")
            if rule_color is not None:
                y1 = pdf.get_y()
                pdf.set_draw_color(*rule_color)
                pdf.set_line_width(0.6)
                x = pdf.l_margin + max(indent - 3, 0.3)
                pdf.line(x, y0, x, y1)
            first_chunk = False
            if i < len(lines):
                pdf.add_page()

    def evidence_block(self, ref_label, text, *, truncated=False):
        """Evidence as data: a small line-reference label over a mono
        block on a panel fill — never a justified paragraph. A block
        longer than a page SPLITS across pages with a "(continued)"
        label and the recurring header/footer intact (A1 P2-3). The
        projection's text_truncated flag is disclosed, never hidden."""
        pdf = self
        if ref_label:
            self.font("", 7.5, mono=True)
            pdf.set_text_color(*self.tokens.muted)
            pdf.multi_cell(0, 4.5, self._t(ref_label, mono=True),
                           align="L", new_x="LMARGIN", new_y="NEXT")
        self.font("", 8.5, mono=True)
        width = pdf.w - pdf.l_margin - pdf.r_margin
        lines = self._split_lines(self._t(text, mono=True), width, 5)
        self._flow_lines(
            lines, 5, ("", 8.5, True), self.tokens.ink, fill=True,
            rule_color=self.tokens.accent,
            continued_label=(f"{ref_label} (continued)" if ref_label
                             else "(continued)"))
        if truncated:
            self.font("", 8, mono=True)
            pdf.set_text_color(*self.tokens.muted)
            pdf.multi_cell(0, 4.5, self._t(
                "[excerpt truncated in the source artifact]", mono=True),
                align="L", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*self.tokens.ink)
        pdf.ln(1.5)

    def limitation_note(self, text):
        """Limitations as a visually distinct muted, ruled note —
        present and legible, never hidden or softened. The rule is
        drawn per page segment so a split note stays ruled."""
        pdf = self
        self.font("", 9)
        width = pdf.w - pdf.l_margin - pdf.r_margin - 4
        lines = self._split_lines(self._t(text), width, 5.2)
        self._flow_lines(lines, 5.2, ("", 9, False),
                         self.tokens.limitation, indent=4,
                         rule_color=self.tokens.limitation)
        pdf.set_text_color(*self.tokens.ink)
        pdf.ln(1)

    def group_heading(self, level, template, count):
        """Structured group heading: severity chip + count badge on one
        row, template name as its own wrapped line — structured data,
        never a key=value string stretched across the measure. The
        template wraps via multi_cell, however long it is (A1 P2-3)."""
        pdf = self
        if pdf.get_y() + 18 > pdf.h - pdf.b_margin:
            pdf.add_page()
        pdf.ln(4)
        level_text = str(level or "").upper()
        color = self.tokens.severity.get(level_text, self.tokens.muted)
        self.font("B", 8.5)
        chip_w = pdf.get_string_width(self._t(level_text)) + 6
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(chip_w, 6.5, self._t(level_text), fill=True, align="C",
                 new_x="RIGHT", new_y="TOP")
        pdf.set_text_color(*self.tokens.muted)
        self.font("B", 9.5)
        pdf.cell(0, 6.5, self._t(f"  × {count}"), new_x="LMARGIN",
                 new_y="NEXT")
        pdf.set_text_color(*self.tokens.navy)
        self.font("B", 12)
        pdf.multi_cell(0, 7, self._t(template), align="L",
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*self.tokens.ink)
        pdf.ln(1)


def render_brief_slot(pdf_view, projection):
    """Issue #162: the Investigation Brief front section, rendered
    here in the seam #160 reserved (decision 7) — directly from
    public_projection()["brief"] with the designed renderer's own
    methods (Amendment A1 / P1-2: projection_text_lines() has no
    caller in the PDF path). A legacy artifact with no brief key
    projects brief=None and renders no brief section."""
    brief = (projection or {}).get("brief")
    if not brief:
        return None
    view = pdf_view
    view.section_heading("Investigation Brief")
    for sentence in brief.get("summary") or []:
        view.para(sentence)
    lead = brief.get("lead")
    if lead:
        view.subhead(f"Investigation lead: {lead.get('template')} "
                     f"x {lead.get('count')}")
        if lead.get("symptom"):
            view.para(f"Explanation: {lead['symptom']}")
        if lead.get("cause"):
            view.para(f"What this may mean: {lead['cause']}")
        for excerpt in lead.get("excerpts") or []:
            view.evidence_block(
                f"analysis line {excerpt.get('analysis_line_number')}",
                excerpt.get("text") or "",
                truncated=bool(excerpt.get("text_truncated")))
        for limit in lead.get("limitations") or []:
            view.limitation_note(limit)
    why = brief.get("why_first")
    if why:
        if why.get("statement"):
            view.para(why["statement"])
        if why.get("facts"):
            view.para(why["facts"])
        if why.get("limitation"):
            view.limitation_note(why["limitation"])
    sequence = brief.get("sequence")
    if sequence:
        view.subhead("Observed sequence")
        if sequence.get("caption"):
            view.para(sequence["caption"], style="I")
        for entry in sequence.get("entries") or []:
            span = entry.get("first_seen") or ""
            if entry.get("last_seen") and \
                    entry.get("last_seen") != entry.get("first_seen"):
                span = f"{span} - {entry['last_seen']}"
            view.para(f"{span}: {entry.get('template')}")
    checks = brief.get("priority_checks") or []
    if checks:
        view.subhead("Priority checks")
        for check in checks:
            view.para(f"Check: {check.get('text')}")
            if check.get("motivation"):
                view.para(f"Motivation: {check['motivation']}", size=9)
            if check.get("support"):
                view.para(check["support"], size=9)
            if check.get("weaken"):
                view.para(check["weaken"], size=9)
    for limit in brief.get("limitations") or []:
        view.limitation_note(limit)
    return None


def generate_report_pdf(manifest_json: str, filename: str = "report",
                        branding: dict | None = None) -> bytes:
    """Generate a PDF report from a stored analysis result.

    Args:
        manifest_json: The Result.storage_manifest JSON (analysis data).
        filename: Original log filename for the report header.
        branding: Optional issue-#163 branding seam (business name /
            logo path / accent override / report title / client name).
            Parameter only — no settings UI or persistence here.

    Returns:
        PDF file bytes.
    """
    from fpdf import FPDF

    try:
        data = json.loads(manifest_json)
    except (json.JSONDecodeError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    view = _DesignedPDF(title="StackSift Analysis Report",
                        filename=filename, branding=branding)
    pdf = view
    pdf.add_page()
    view.header_block()
    if data.get("detected_format"):
        # Rendered by the pre-#160 header; kept in the designed one
        # (content-to-rendering inventory, A1 P2-3).
        view.text_line(f"Format: {data['detected_format']}", size=10,
                       color=view.tokens.muted)

    def heading(text):
        view.section_heading(text)

    def line(text, size=11, style="", height=7, color=None):
        view.text_line(text, size=size, style=style, height=height,
                       color=color)

    def para(text, size=10, style="", color=None):
        view.para(text, size=size, style=style, color=color)

    results = data.get("results") or {}
    sorted_issues = data.get("sorted_issues") or []

    # Summary
    health = data.get("health") or {}
    if health:
        heading("Summary")
        label = health.get("label", "Unknown")
        line(f"Health: {label}", size=12, style="B",
             color=_health_color(health))
        if data.get("first_seen") and data.get("last_seen"):
            line(f"Window: {data['first_seen']} to {data['last_seen']}", size=10)
        if data.get("elapsed"):
            line(f"Analysis time: {data['elapsed']:.2f}s", size=10)

    # Complexity notice — warning orange, preserved through the
    # designed para() via its explicit color argument (PR #165 Codex
    # P2: the design layer previously reset every paragraph to ink).
    if data.get("complexity_truncated") and data.get("complexity_notice"):
        para(data["complexity_notice"], style="I", color=(217, 119, 6))

    # Statistics
    if results:
        heading("Statistics")
        if "total_lines" in results:
            line(f"Total Lines: {results['total_lines']}")
        if "parsed_lines" in results:
            line(f"Parsed Lines: {results['parsed_lines']}")
        if "malformed_lines" in results:
            line(f"Malformed Lines: {results['malformed_lines']}")
        line(f"Unique Issues: {len(sorted_issues)}")

    # Investigate first
    diagnostic = data.get("diagnostic_issue")
    if diagnostic:
        heading("Investigate First")
        template, detail = diagnostic[0], diagnostic[1] or {}
        line(f"[{detail.get('level', '')}] {template} (x{detail.get('count', '')})")
        for point in data.get("diagnostic_explanation") or []:
            para(f"- {point}")

    # Incident — Issue #170 S1 (Decision 14 as amended by A3): the
    # numbered heading aligns the standard PDF with the web Report
    # surface, and the Observed/Correlated/Hypothesized groups below
    # NEWLY DISPLAY existing supporting_evidence data in the standard
    # PDF (it rendered none before this slice — a content addition,
    # not a rename). Captions are the A1 membership-faithful strings.
    # The 'none' branch carries no supporting_evidence key: guarded.
    incident = data.get("incident_section") or {}
    if incident:
        heading("01 Incident")
        if incident.get("type") == "none":
            if incident.get("message"):
                para(incident["message"])
        else:
            if incident.get("headline"):
                line(incident["headline"], style="B")
            if incident.get("investigate_first"):
                para(f"Investigate first: {incident['investigate_first']}")
            if incident.get("starting_point"):
                line(f"Starting point: {incident['starting_point']}", size=10)
            if incident.get("timing_note"):
                para(incident["timing_note"], style="I")
            _se = incident.get("supporting_evidence") or {}
            for _key, _label, _caption in (
                ("observed", "Observed",
                 "Shares infrastructure with the lead issue."),
                ("correlated", "Correlated",
                 "Appears in the same time pattern as the lead issue; "
                 "no shared cause is established."),
                ("hypothesized", "Hypothesized",
                 "Shares infrastructure with the lead issue and shows "
                 "a possible contributor signal \u2014 unproven."),
            ):
                _items = _se.get(_key) or []
                if not _items:
                    continue
                line(_label, size=11, style="B")
                para(_caption, size=9)
                for _item in _items:
                    para(f"[{_item[2]}] {_item[0]} (x{_item[1]})", size=10)
                _total = _se.get(f"{_key}_total", len(_items))
                if _total > len(_items):
                    para(f"{_total - len(_items)} more not shown",
                         size=9, style="I")

    # Notable events
    notable = data.get("notable_events") or []
    if notable:
        heading("02 Notable Events")
        for event in notable:
            para(f"[{event.get('level', '')}] {event.get('template', '')} "
                 f"(x{event.get('count', '')})")

    # Timeline
    timeline = data.get("timeline") or []
    if len(timeline) > 1:
        # Keep the heading with the chart: if heading + subtitle + chart +
        # legend would not fit on this page, start the section on a new one.
        if pdf.get_y() + 66 > pdf.h - pdf.b_margin:
            pdf.add_page()
        heading("03 Timeline")
        line("Warnings + errors per 5 min", size=10)
        totals = [
            (b.get("critical", 0) or 0) + (b.get("error", 0) or 0)
            + (b.get("warn", 0) or 0)
            for b in timeline
        ]
        peak = max(totals) if totals else 0
        if peak > 0:
            segments = (
                ("critical", (185, 28, 28), "Critical"),
                ("error", (234, 88, 12), "Error"),
                ("warn", (245, 158, 11), "Warning"),
            )
            chart_h = 32
            x0 = pdf.l_margin
            chart_w = pdf.w - pdf.l_margin - pdf.r_margin
            top = pdf.get_y() + 2
            n = len(timeline)
            slot = chart_w / n
            bar_w = min(max(1.0, slot * 0.7), 14.0)
            for i, bucket in enumerate(timeline):
                x = x0 + i * slot + (slot - bar_w) / 2
                y = top + chart_h
                for key, color, _label in segments:
                    count = bucket.get(key, 0) or 0
                    if count:
                        h = chart_h * count / peak
                        y -= h
                        pdf.set_fill_color(*color)
                        pdf.rect(x, y, bar_w, h, style="F")
            pdf.set_y(top + chart_h + 1)
            # Legend
            lx = x0
            view.font("", 9)
            for _key, color, label in segments:
                pdf.set_fill_color(*color)
                pdf.rect(lx, pdf.get_y() + 1, 3, 3, style="F")
                pdf.set_xy(lx + 4, pdf.get_y())
                pdf.cell(18, 5, view._t(label))
                lx += 24
            pdf.set_y(pdf.get_y() + 6)
            line(f"Totals: {sum(b.get('critical', 0) or 0 for b in timeline)} critical, "
                 f"{sum(b.get('error', 0) or 0 for b in timeline)} errors, "
                 f"{sum(b.get('warn', 0) or 0 for b in timeline)} warnings "
                 f"across {n} buckets (peak bucket: {peak})", size=9)
            if n <= 12:
                for bucket in timeline:
                    line(f"{bucket.get('label', '')}: "
                         f"{bucket.get('critical', 0)} critical, "
                         f"{bucket.get('error', 0)} errors, "
                         f"{bucket.get('warn', 0)} warnings", size=10)
        else:
            for bucket in timeline:
                line(f"{bucket.get('label', '')}: "
                     f"{bucket.get('critical', 0)} critical, "
                     f"{bucket.get('error', 0)} errors, "
                     f"{bucket.get('warn', 0)} warnings", size=10)

    # All issues
    if sorted_issues:
        heading("04 All Issues")
        for template, detail in sorted_issues[:MAX_ISSUES]:
            detail = detail or {}
            line(f"[{detail.get('level', '')}] (x{detail.get('count', '')})",
                 size=10, style="B")
            para(str(template))
        if len(sorted_issues) > MAX_ISSUES:
            para(f"... and {len(sorted_issues) - MAX_ISSUES} more issue patterns "
                 f"not shown.", style="I")
    elif results:
        heading("04 All Issues")
        para("No warnings, errors, or critical entries found.")

    # Analysis notices — Issue #170 S1 §05: the malformed-lines notice
    # keeps its exact base text, gathered under the numbered heading
    # with the adapted-format notice (web parity).
    if results.get("malformed_lines", 0) > 0 or data.get("adapted"):
        heading("05 Analysis Notices")
    if results.get("malformed_lines", 0) > 0:
        para(f"{results['malformed_lines']} lines could not be parsed and were "
             f"excluded.", style="I")
    if data.get("adapted"):
        para("Your file was detected as JSON-lines and converted "
             "automatically.", style="I")


    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def generate_deep_dive_pdf(manifest_json: str, filename: str = "report",
                           branding: dict | None = None) -> bytes:
    """PDF for an Analysis Report (issue #106 Stage 2).

    Renders ONLY the artifact's public projection (plain-language
    claims, excerpts, limitations) — no internal evidence refs,
    digests, scores or labels. Export charging is the caller's #129
    per-report unlock; there is no separate Analysis PDF price.
    Issue #160: shares the designed layer with the standard report.
    """
    from fpdf import FPDF

    from app import deep_dive as _dd

    try:
        data = json.loads(manifest_json)
    except (json.JSONDecodeError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    projection = _dd.public_projection(_dd.validate_artifact(data))

    view = _DesignedPDF(title="StackSift Analysis Report",
                        filename=filename, branding=branding)
    pdf = view
    pdf.add_page()
    view.header_block()

    # (a) summary as a distinct panel, then (b) the #162 Brief slot,
    # then (c) one structured section per group (decision 5 order).
    view.section_heading("Summary")
    view.summary_panel(projection.get("summary") or "")
    render_brief_slot(view, projection)

    for group in projection.get("groups") or []:
        view.group_heading(group.get("level"), group.get("template"),
                           group.get("count"))
        for label, key in (
                ("What was observed", "observations"),
                ("Explanation", "explanations"),
                ("What this may mean", "possible_causes"),
                ("Suggested first checks", "first_checks")):
            items = group.get(key) or []
            if not items:
                continue  # empty subsections are omitted
            view.subhead(label)
            for text in items:
                view.para(text)
        excerpts = group.get("excerpts") or []
        if excerpts:
            view.subhead("Evidence")
            for excerpt in excerpts:
                view.evidence_block(
                    f"analysis line {excerpt.get('analysis_line_number')}",
                    excerpt.get("text") or "",
                    truncated=bool(excerpt.get("text_truncated")))
        limitations = group.get("limitations") or []
        if limitations:
            view.subhead("Limitations")
            for limit in limitations:
                view.limitation_note(limit)


    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def generate_batch_pdf(manifest_json: str, filename: str = "batch") -> bytes:
    """Generate a PDF for a stored batch payload (issue #103, trim B5).

    ONE export covers the whole combined artifact (COST_PDF charged
    once by the route, never per file). Every file section is rendered;
    the per-file issue list honors MAX_ISSUES PER SECTION and discloses
    the omitted count for that section — whole sections are never
    silently omitted, and neither are the combined-issue attributions
    beyond the same disclosed cap.
    """
    from fpdf import FPDF

    try:
        data = json.loads(manifest_json)
    except (json.JSONDecodeError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    pdf = FPDF()
    pdf.set_compression(False)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    def heading(text):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*NAVY)
        pdf.cell(0, 10, _s(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*BLACK)

    def line(text, size=11, style="", height=7):
        pdf.set_font("Helvetica", style, size)
        pdf.cell(0, height, _s(text), new_x="LMARGIN", new_y="NEXT")

    def para(text, size=10, style=""):
        pdf.set_font("Helvetica", style, size)
        pdf.multi_cell(0, 6, _s(text))
        pdf.ln(1)

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 12, "StackSift Batch Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 8, _s(f"Batch: {filename}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*BLACK)
    pdf.ln(3)

    summary = data.get("summary") or {}
    heading("Combined Summary")
    line(f"Files: {summary.get('file_count', len(data.get('files') or []))}")
    line(f"Total Lines: {summary.get('total_lines', 0)}")
    line(f"Parsed Lines: {summary.get('parsed_lines', 0)}")
    line(f"Malformed Lines: {summary.get('malformed_lines', 0)}")
    line(f"Unique Issue Patterns: {summary.get('unique_issue_patterns', 0)}")
    if data.get("summary_sentence"):
        para(data["summary_sentence"])
    levels = summary.get("level_counts") or {}
    for level in ("CRITICAL", "ERROR", "WARN", "INFO"):
        if level in levels:
            line(f"{level}: {levels[level]}", size=10)

    combined = data.get("combined_issues") or []
    heading(f"Combined Issues ({len(combined)})")
    if not combined:
        para("No warnings, errors, or critical entries found.")
    for entry in combined[:MAX_ISSUES]:
        line(f"(x{entry.get('count', 0)})", size=10, style="B")
        para(str(entry.get("template", "")))
        for attribution in entry.get("files") or []:
            line(f"  File {attribution.get('ordinal')}: {attribution.get('filename', '')} "
                 f"(x{attribution.get('count', 0)})", size=9)
    if len(combined) > MAX_ISSUES:
        para(f"... and {len(combined) - MAX_ISSUES} more combined issue patterns "
             f"not shown.", style="I")

    for section in data.get("files") or []:
        report = section.get("report") or {}
        results = report.get("results") or {}
        heading(f"File {section.get('ordinal')}: {section.get('filename', '')}")
        if report.get("health"):
            line(f"Health: {(report['health'] or {}).get('label', '')}", size=10)
        line(f"Total Lines: {results.get('total_lines', 0)}", size=10)
        line(f"Parsed Lines: {results.get('parsed_lines', 0)}", size=10)
        line(f"Malformed Lines: {results.get('malformed_lines', 0)}", size=10)
        if report.get("complexity_truncated") and report.get("complexity_notice"):
            para(report["complexity_notice"], style="I")
        diagnostic = report.get("diagnostic_issue")
        if diagnostic:
            detail = diagnostic[1] or {}
            line(f"Investigate first: [{detail.get('level', '')}] "
                 f"{diagnostic[0]} (x{detail.get('count', '')})",
                 size=10, style="B")
            for point in report.get("diagnostic_explanation") or []:
                para(f"- {point}")
        timeline = report.get("timeline") or []
        if len(timeline) > 1:
            line("Timeline: warnings + errors per 5 min — "
                 f"{sum(b.get('critical', 0) or 0 for b in timeline)} critical, "
                 f"{sum(b.get('error', 0) or 0 for b in timeline)} errors, "
                 f"{sum(b.get('warn', 0) or 0 for b in timeline)} warnings "
                 f"across {len(timeline)} buckets", size=10)
            if len(timeline) <= 12:
                for bucket in timeline:
                    line(f"{bucket.get('label', '')}: "
                         f"{bucket.get('critical', 0)} critical, "
                         f"{bucket.get('error', 0)} errors, "
                         f"{bucket.get('warn', 0)} warnings", size=10)
        issues = report.get("sorted_issues") or []
        if issues:
            for template, detail in issues[:MAX_ISSUES]:
                detail = detail or {}
                line(f"[{detail.get('level', '')}] (x{detail.get('count', '')})",
                     size=10, style="B")
                para(str(template))
            if len(issues) > MAX_ISSUES:
                para(f"... and {len(issues) - MAX_ISSUES} more issue patterns "
                     f"in this file not shown.", style="I")
        else:
            para("No warnings, errors, or critical entries found in this file.")

    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 8, "Generated by StackSift (stacksift.goodfolkdigital.com)",
             new_x="LMARGIN", new_y="NEXT", align="C")

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def generate_comparison_pdf(manifest_json: str, filename: str = "comparison") -> bytes:
    """Generate a PDF for a stored comparison payload (issue #102).

    Approved spec trim C4: NO silent truncation — every change entry in
    every section is rendered (fpdf paginates automatically). The shared
    section is summarized by counts only: shared groups are, by
    definition, not changes, and listing hundreds of unchanged groups
    would bury the diff; the summary states the shared count honestly.
    No diagnostic scores or internal labels appear in the output.
    """
    from fpdf import FPDF

    try:
        data = json.loads(manifest_json)
    except (json.JSONDecodeError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    pdf = FPDF()
    # Uncompressed so the diff text is directly searchable in the file
    # (and in tests); comparison PDFs are small.
    pdf.set_compression(False)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    def heading(text):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*NAVY)
        pdf.cell(0, 10, _s(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*BLACK)

    def line(text, size=11, style="", height=7):
        pdf.set_font("Helvetica", style, size)
        pdf.cell(0, height, _s(text), new_x="LMARGIN", new_y="NEXT")

    def para(text, size=10, style=""):
        pdf.set_font("Helvetica", style, size)
        pdf.multi_cell(0, 6, _s(text))
        pdf.ln(1)

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 12, "StackSift Comparison Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 8, _s(f"Files: {filename}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*BLACK)
    pdf.ln(3)

    inputs = data.get("inputs") or {}
    a_in = inputs.get("a") or {}
    b_in = inputs.get("b") or {}
    heading("Summary")
    summary = data.get("summary") or {}
    line(f"New in B: {summary.get('new', len(data.get('new') or []))}")
    line(f"Resolved (absent from B): {summary.get('resolved', len(data.get('resolved') or []))}")
    line(f"Volume changed: {summary.get('volume_changed', len(data.get('volume_changes') or []))}")
    line(f"Severity shifted: {summary.get('severity_shifted', len(data.get('severity_shifts') or []))}")
    line(f"Shared (unchanged identity): {len(data.get('shared') or [])}")
    if data.get("no_material_differences"):
        para("No material differences were found between the two logs.")
    if data.get("resolved_note"):
        para(data["resolved_note"], style="I")
    if a_in or b_in:
        para(f"A (before): {a_in.get('filename', '')} — "
             f"{a_in.get('total_lines', 0)} lines, {a_in.get('parsed_lines', 0)} parsed. "
             f"B (after): {b_in.get('filename', '')} — "
             f"{b_in.get('total_lines', 0)} lines, {b_in.get('parsed_lines', 0)} parsed.")

    def entry_line(entry, severity_transition=False):
        a_sev = entry.get("a_highest_severity") or ""
        b_sev = entry.get("b_highest_severity") or ""
        if severity_transition and a_sev and b_sev:
            # A severity shift is only meaningful as a transition: rendering
            # just the B severity makes an escalation and an improvement at
            # the same counts indistinguishable (issue #117).
            sev = f"{a_sev} -> {b_sev}"
        else:
            sev = b_sev or a_sev
        line(f"[{sev}] {entry.get('a_count', 0)} -> {entry.get('b_count', 0)}",
             size=10, style="B")
        para(str(entry.get("template", "")))

    for title, key in (("New in B", "new"), ("Resolved", "resolved"),
                       ("Volume Changes", "volume_changes"),
                       ("Severity Shifts", "severity_shifts")):
        entries = data.get(key) or []
        heading(f"{title} ({len(entries)})")
        if not entries:
            para("None.")
        for entry in entries:
            entry_line(entry, severity_transition=(key == "severity_shifts"))

    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 8, "Generated by StackSift (stacksift.goodfolkdigital.com)",
             new_x="LMARGIN", new_y="NEXT", align="C")

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()
