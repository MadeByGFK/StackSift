"""PDF export for StackSift analysis reports (Phase 2B).

Generates a PDF from a stored analysis result's storage_manifest JSON.
The PDF mirrors the on-screen report: summary, statistics, investigate-first
diagnostic, incident section, notable events, timeline, and all issues.
Uses fpdf2 (pure Python, no system dependencies).
"""

import json
from datetime import datetime, timezone
from io import BytesIO

NAVY = (30, 42, 74)
GRAY = (100, 100, 100)
BLACK = (0, 0, 0)
HEALTH_COLORS = {
    "Critical": (185, 28, 28),
    "Warning": (217, 119, 6),
    "Healthy": (22, 163, 74),
}
MAX_ISSUES = 100


_PUNCT_MAP = {
    "“": '"', "”": '"', "‘": "'", "’": "'",
    "–": "-", "—": "-", "•": "-", "…": "...",
}


def _s(text) -> str:
    """Coerce to str and make it safe for fpdf2 core fonts (latin-1 only).

    Common cp1252 punctuation is mapped to ASCII equivalents first;
    anything still outside latin-1 is replaced.
    """
    text = str(text)
    for src, dst in _PUNCT_MAP.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", "replace").decode("latin-1")


def generate_report_pdf(manifest_json: str, filename: str = "report") -> bytes:
    """Generate a PDF report from a stored analysis result.

    Args:
        manifest_json: The Result.storage_manifest JSON (analysis data).
        filename: Original log filename for the report header.

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

    pdf = FPDF()
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

    # Header
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 12, "StackSift Analysis Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 8, _s(f"File: {filename}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
             new_x="LMARGIN", new_y="NEXT")
    if data.get("detected_format"):
        pdf.cell(0, 8, _s(f"Format: {data['detected_format']}"),
                 new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*BLACK)
    pdf.ln(3)

    results = data.get("results") or {}
    sorted_issues = data.get("sorted_issues") or []

    # Summary
    health = data.get("health") or {}
    if health:
        heading("Summary")
        label = health.get("label", "Unknown")
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*HEALTH_COLORS.get(label, BLACK))
        pdf.cell(0, 8, _s(f"Health: {label}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*BLACK)
        if data.get("first_seen") and data.get("last_seen"):
            line(f"Window: {data['first_seen']} to {data['last_seen']}", size=10)
        if data.get("elapsed"):
            line(f"Analysis time: {data['elapsed']:.2f}s", size=10)

    # Complexity notice
    if data.get("complexity_truncated") and data.get("complexity_notice"):
        pdf.set_text_color(217, 119, 6)
        para(data["complexity_notice"], style="I")
        pdf.set_text_color(*BLACK)

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

    # Incident
    incident = data.get("incident_section") or {}
    if incident:
        heading("Incident")
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

    # Notable events
    notable = data.get("notable_events") or []
    if notable:
        heading("Notable Events")
        for event in notable:
            para(f"[{event.get('level', '')}] {event.get('template', '')} "
                 f"(x{event.get('count', '')})")

    # Timeline
    timeline = data.get("timeline") or []
    if len(timeline) > 1:
        heading("Timeline")
        line("Warnings + errors per 5 min", size=10)
        for bucket in timeline:
            line(f"{bucket.get('label', '')}: {bucket.get('critical', 0)} critical, "
                 f"{bucket.get('error', 0)} errors, {bucket.get('warn', 0)} warnings",
                 size=10)

    # All issues
    if sorted_issues:
        heading("All Issues")
        for template, detail in sorted_issues[:MAX_ISSUES]:
            detail = detail or {}
            line(f"[{detail.get('level', '')}] (x{detail.get('count', '')})",
                 size=10, style="B")
            para(str(template))
        if len(sorted_issues) > MAX_ISSUES:
            para(f"... and {len(sorted_issues) - MAX_ISSUES} more issue patterns "
                 f"not shown.", style="I")
    elif results:
        heading("All Issues")
        para("No warnings, errors, or critical entries found.")

    # Malformed notice
    if results.get("malformed_lines", 0) > 0:
        para(f"{results['malformed_lines']} lines could not be parsed and were "
             f"excluded.", style="I")

    # Footer
    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 8, "Generated by StackSift (stacksift.goodfolkdigital.com)",
             new_x="LMARGIN", new_y="NEXT", align="C")

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()
