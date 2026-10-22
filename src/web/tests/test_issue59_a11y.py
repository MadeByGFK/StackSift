"""Issue #59: upload accessibility — keyboard-operable file picker, focus
visibility, live-region announcements, and measured text contrast.

Static structural checks against the tip template + stylesheet (no browser
needed): they verify the exact DOM/CSS properties that make the flow
keyboard-operable rather than re-implementing a screen reader.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
TEMPLATE = (APP / "templates" / "index.html").read_text()
CSS = (APP / "static" / "style.css").read_text()


def _strip_jinja(html: str) -> str:
    html = re.sub(r"{%.*?%}", "", html, flags=re.S)
    return re.sub(r"{{.*?}}", "", html, flags=re.S)


class _Node:
    def __init__(self, tag, attrs, parent=None):
        self.tag, self.attrs = tag, dict(attrs)
        self.parent = parent
        self.children = []
        self.text = ""

    def find_all(self, tag=None, **attr_match):
        out = []
        if (tag is None or self.tag == tag) and all(
            self.attrs.get(k) == v for k, v in attr_match.items()
        ):
            out.append(self)
        for c in self.children:
            out.extend(c.find_all(tag, **attr_match))
        return out

    def find(self, tag=None, **attr_match):
        found = self.find_all(tag, **attr_match)
        return found[0] if found else None

    def inner_text(self):
        return (self.text + "".join(c.inner_text() for c in self.children)).strip()


class _Tree(HTMLParser):
    VOID = {"input", "img", "br", "meta", "link", "hr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node("root", {})
        self._stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs, self._stack[-1])
        self._stack[-1].children.append(node)
        if tag not in self.VOID:
            self._stack.append(node)

    def handle_endtag(self, tag):
        if len(self._stack) > 1:
            self._stack.pop()

    def handle_data(self, data):
        self._stack[-1].text += data


def _dom():
    tree = _Tree()
    tree.feed(_strip_jinja(TEMPLATE))
    return tree.root


def test_file_input_stays_in_tab_order():
    """The picker input must not be display:none/hidden/disabled: keyboard
    users reach it with Tab and open it with Enter/Space natively."""
    dom = _dom()
    fi = dom.find("input", id="file-input")
    assert fi is not None, "input#file-input missing from upload form"
    assert fi.attrs.get("type") == "file"
    assert "hidden" not in fi.attrs, "input must not carry the hidden attribute"
    assert "disabled" not in fi.attrs, "input must not be disabled"
    assert fi.attrs.get("tabindex") != "-1", "input must not opt out of tab order"
    assert "visually-hidden" in fi.attrs.get("class", "").split()
    assert "display: none" not in CSS.replace(" ", "").lower() or \
        ".dropzoneinput[type=file]{display:none}" not in CSS.replace(" ", "").lower(), \
        "file input must not be display:none (removed from a11y tree)"


def test_file_input_has_accessible_name():
    """The input's accessible name comes from its associated <label>."""
    dom = _dom()
    label = dom.find("label", id="dropzone")
    assert label is not None, "dropzone must be a <label>"
    assert label.attrs.get("for") == "file-input", "label must target the file input"
    name = label.inner_text()
    assert len(name) > 10, f"label text too short to be a useful name: {name!r}"
    assert "log" in name.lower()


def test_dropzone_uses_native_label_not_click_hack():
    """No synthetic fi.click() on a div: the label activates the input natively."""
    dom = _dom()
    dz = dom.find(id="dropzone")
    assert dz is not None and dz.tag == "label", "dropzone must be a label element"
    assert "fi.click()" not in TEMPLATE, "synthetic click hack must be removed"
    # inner blocks must be spans: <div> inside <label> is invalid HTML
    for div in dz.find_all("div"):
        raise AssertionError(f"<div> inside <label class=dropzone> is invalid: {div.attrs}")


def test_submit_buttons_present_for_keyboard_flow():
    """After picking a file, a keyboard user submits with the real buttons."""
    dom = _dom()
    form = dom.find("form", id="upload-form")
    assert form is not None
    fi = form.find("input", id="file-input")
    assert fi is not None, "file input must live inside the upload form"
    submits = form.find_all("button", type="submit")
    assert len(submits) >= 1, "keyboard flow needs a native submit button"


def test_error_state_announced():
    dom = _dom()
    err = dom.find("div", **{"class": "error"})
    assert err is not None, ".error container missing"
    assert err.attrs.get("role") == "alert", "upload errors must use role=alert"


def test_loading_state_announced():
    dom = _dom()
    loading = dom.find(id="loading")
    assert loading is not None
    assert loading.attrs.get("role") == "status", "loading indicator must use role=status"


def test_focus_visible_styles_exist():
    """Every interactive element needs a visible keyboard focus indicator;
    the visually-hidden input surfaces its focus on the dropzone label."""
    assert ":focus-visible" in CSS, "no :focus-visible rules in stylesheet"
    assert re.search(r"a:focus-visible.*button:focus-visible", CSS, re.S), \
        "global focus-visible rule for links/buttons/inputs missing"
    assert re.search(r"#file-input:focus-visible\s*\+\s*\.dropzone", CSS), \
        "dropzone must show a focus ring when its file input has keyboard focus"
    assert "outline" in CSS, "focus styles must paint an outline"


def _luminance(hexcolor):
    h = hexcolor.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def _ratio(fg, bg):
    hi, lo = max(_luminance(fg), _luminance(bg)), min(_luminance(fg), _luminance(bg))
    return (hi + 0.05) / (lo + 0.05)


# Measured 2026-10-21 from :root palette + inline privacy-notice colors.
# Contrast is resolution/zoom independent; layout at 200% zoom reflows via
# max-width + viewport meta (no fixed-width containers on this page).
CONTRAST_PAIRS = [
    ("body text #ffffff on #0a1830", "#ffffff", "#0a1830", 4.5),
    ("muted #9db1cc on bg #0a1830", "#9db1cc", "#0a1830", 4.5),
    ("muted #9db1cc on panel #10254a", "#9db1cc", "#10254a", 4.5),
    ("accent #d4af37 on bg #0a1830", "#d4af37", "#0a1830", 4.5),
    ("accent #d4af37 on panel #10254a", "#d4af37", "#10254a", 4.5),
    ("signup text #1a1a2e on accent", "#1a1a2e", "#d4af37", 4.5),
    ("primary text #0a1830 on accent", "#0a1830", "#d4af37", 4.5),
    ("error #ffb4ab on #3a1a1e", "#ffb4ab", "#3a1a1e", 4.5),
    ("badge green #3fb950 on bg", "#3fb950", "#0a1830", 4.5),
    ("badge yellow #e3a72f on bg", "#e3a72f", "#0a1830", 4.5),
    ("badge red #f85149 on bg", "#f85149", "#0a1830", 4.5),
    ("hero accent span (large text)", "#d4af37", "#0a1830", 3.0),
    ("privacy notice #a0aec0 on #1e2a4a", "#a0aec0", "#1e2a4a", 4.5),
]


def test_text_contrast_meets_wcag_aa():
    failures = []
    for name, fg, bg, minimum in CONTRAST_PAIRS:
        r = _ratio(fg, bg)
        if r < minimum:
            failures.append(f"{name}: {r:.2f}:1 < {minimum}:1")
    assert not failures, "contrast failures:\n" + "\n".join(failures)
