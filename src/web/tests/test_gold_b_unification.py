"""Gold-B unification (founder ruling B, 2026-11-16): #e3a72f is THE brand
gold. #d4af37 and #ecc94b are retired; WARN (--yellow) moved to #d29922 so
it no longer collides with the brand accent.

These pins keep a retired gold from creeping back into the token layer,
the templates, or the PDF brand table.
"""
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
CSS = (APP / "static" / "style.css").read_text(encoding="utf-8")


def _root_var(name):
    root = re.search(r":root \{(.*?)\}", CSS, re.DOTALL).group(1)
    return re.search(rf"{re.escape(name)}:\s*(#[0-9a-fA-F]{{6}})",
                     root).group(1).lower()


def test_accent_is_the_brand_gold():
    assert _root_var("--accent") == "#e3a72f"


def test_yellow_is_the_warn_gold_not_the_brand_gold():
    assert _root_var("--yellow") == "#d29922"


def test_pdf_brand_gold_matches():
    from app.pdf_export import BRAND
    assert BRAND["gold"] == (227, 167, 47)


def test_sample_accent_matches():
    from app.branding import SAMPLE_ACCENT
    assert SAMPLE_ACCENT == "#e3a72f"


def test_no_retired_gold_literals_in_app_text_files():
    offenders = []
    for path in sorted(APP.rglob("*")):
        if path.suffix not in (".html", ".css", ".py", ".svg"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        for retired in ("#d4af37", "#ecc94b"):
            if retired in text:
                offenders.append(f"{path.relative_to(APP)}: {retired}")
    assert not offenders, "retired gold literals remain:\n" + "\n".join(offenders)
