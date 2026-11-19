"""Issue #142b — Settings → Branding port: page-contract tests.

The port moves group 02 to the Lovable prototype's structure: numbered
heading INSIDE the panel, hairline field rows with themed inputs, a
swatch+hex accent control, a dashed logo drop zone (copy truthful to
the live PNG/JPEG contract), the attribution note above one save row
carrying Save (gold primary) and Clear (ghost, CALL-1 default: kept).
Form actions, field names, maxlengths and CSRF are unchanged.
"""
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
SETTINGS = (APP / "templates" / "settings.html").read_text(encoding="utf-8")
CSS = (APP / "static" / "style.css").read_text(encoding="utf-8")

PANEL = SETTINGS[SETTINGS.index('id="branding-profile"'):
                 SETTINGS.index('data-s4-group="purchases"')]


def test_heading_inside_panel_no_duplicate():
    assert 'class="s4-section-head s4b-head"' in PANEL
    assert '<span class="s4-section-num" aria-hidden="true">02</span>' in PANEL
    assert "Included with every paid report" in PANEL
    assert "<h2>Branding profile</h2>" not in PANEL
    assert "Add your business branding to your reports" not in SETTINGS
    # The outside-the-card head for group 02 is gone: only one
    # "Branding profile" section label remains on the page for 02.
    group02 = SETTINGS[SETTINGS.index('data-s4-group="branding"'):
                       SETTINGS.index('data-s4-group="purchases"')]
    assert group02.count("s4-section-label") == 1


def test_field_rows_in_design_order_with_themed_inputs():
    labels = re.findall(r'class="s4b-field-label"[^>]*>([^<]+)', PANEL)
    assert labels == ["Business name", "Report title", "Client name ",
                      "Accent color", "Logo"], labels
    assert '<span class="s4b-sub">Optional</span>' in PANEL
    for name, maxlen in (("business_name", "80"), ("report_title", "120"),
                         ("client_name", "80")):
        assert f'class="s4b-text-input" id="branding-' in PANEL
        assert f'name="{name}" maxlength="{maxlen}"' in PANEL
    assert PANEL.count('class="s4b-field-row"') == 5


def test_accent_swatch_and_hex_pair():
    assert 'id="branding-accent-swatch" type="color" value="#e3a72f"' in PANEL
    assert 'id="branding-accent-hex" type="text" name="accent"' in PANEL
    assert 'id="branding-accent-error" role="alert" hidden' in PANEL
    assert "Accent color must be a hex color like #1a2b3c." in PANEL
    # The swatch carries no name: the hex stays the submitted value.
    swatch = re.search(r'<input class="s4b-swatch"[^>]*>', PANEL).group(0)
    assert "name=" not in swatch


def test_logo_drop_zone_truthful_copy_and_remove_kept():
    assert 'class="s4b-drop" id="branding-drop" for="branding-logo-input"' in PANEL
    assert "Drop a PNG or JPEG here, or browse" in PANEL
    assert "Drop a PNG or SVG" not in PANEL  # CALL-2: live contract wins
    assert 'id="branding-logo-input" type="file" name="logo" ' \
           'accept="image/png,image/jpeg"' in PANEL
    assert 'name="remove_logo" value="1"' in PANEL  # CALL-3: kept


def test_note_above_single_save_row_with_both_actions():
    note = PANEL.index("s4b-group-note")
    row = PANEL.index("s4b-save-row")
    assert note < row
    assert "attribution always remains on paid reports" in PANEL
    assert '<button type="submit" form="branding-form" ' \
           'class="btn-small btn-primary">Save branding</button>' in PANEL
    assert '<button type="submit" form="branding-clear-form" ' \
           'class="btn-small btn-ghost">Clear branding</button>' in PANEL
    assert 'id="branding-form" method="post" enctype="multipart/form-data" ' \
           'action="/settings/branding"' in PANEL
    assert 'id="branding-clear-form" method="post" ' \
           'action="/settings/branding/clear"' in PANEL


def test_s4b_css_present_and_scoped():
    for rule in (".s4b-field-row {", ".s4b-text-input {", ".s4b-swatch {",
                 ".s4b-drop {", ".s4b-save-row {", ".s4b-group-note {"):
        assert rule in CSS, rule
    assert "grid-template-columns: 200px 1fr" in CSS
    assert "max-width: 380px" in CSS
    # The phone stacking lives in the page-local style (the shared S4
    # tail is selector-guarded and cannot carry an @media prelude).
    assert "@media (max-width: 640px)" in SETTINGS
    assert ".s4b-field-row { grid-template-columns: 1fr; gap: 8px; }" in SETTINGS


def test_branding_js_wired():
    for hook in ("branding-accent-swatch", "branding-accent-hex",
                 "branding-drop", "branding-logo-input",
                 "stopImmediatePropagation", "DataTransfer"):
        assert hook in SETTINGS, hook
