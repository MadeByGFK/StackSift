"""Issue #163: per-report branding for paid Analysis Reports.

Owns the pieces the routes in main.py share:

- logo validation (Amendment A1): Pillow full decode (``verify()`` then
  a fresh open + full ``load()``) with ``MAX_IMAGE_PIXELS`` capped at
  2048x2048 for the validation context, followed by a canonical
  re-encode to the SAME format. The RE-ENCODED bytes are what gets
  stored, so trailing/polyglot payloads never survive by construction.
- text/accent field validation: plain text only, control characters
  rejected, exact ``#rrggbb`` accent or rejection (never reinterpreted).
- branding-dict assembly: the owned path builds it from the stored
  ``report_branding`` row only (the logo is materialised to a
  server-owned temp file with ``delete=False`` and unlinked in a
  ``finally`` — Amendment A8(f)); the sample path (Amendment A5) builds
  it from a server-side constant profile whose logo is the shipped
  WellInstance static asset. ``logo_path`` never comes from request
  data, a URL, or a user-supplied path anywhere in this module.
"""

from __future__ import annotations

import hashlib
import io
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

from PIL import Image

MAX_LOGO_BYTES = 512 * 1024  # 512 KiB (spec Decision 5 / A8)
MAX_LOGO_DIMENSION = 2048
MAX_IMAGE_PIXELS_LIMIT = 4_194_304  # 2048 * 2048 (Amendment A1)
MAX_TEXT_FIELD_BYTES = 1024  # A8(b): raw byte cap before trim/length
BUSINESS_NAME_MAX = 80
CLIENT_NAME_MAX = 80
REPORT_TITLE_MAX = 120

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

_STATIC_DIR = Path(__file__).resolve().parent / "static"


class BrandingError(ValueError):
    """A branding submission is invalid; the route answers 400."""


# ---------------------------------------------------------------------------
# Logo validation (A1)
# ---------------------------------------------------------------------------

def _metadata_free_image(image):
    """Return a pixel-identical copy of ``image`` with empty metadata.

    Remediation (Codex P2 on PR #169): the decoded image object still
    carries ``im.info`` into the encoder — Pillow's PNG writer falls
    back to ``im.info["icc_profile"]`` and writes it back out, so an
    attacker-controlled iCCP profile survived the canonical re-encode
    byte-identically. Rebuilding from the raw pixel bytes drops the
    ICC profile, text chunks, EXIF and anything else the decoder
    attached. Palette images are expanded first, because their
    palette/transparency live outside the pixel bytes.
    """
    if image.mode == "P":
        image = image.convert(
            "RGBA" if "transparency" in image.info else "RGB")
    return Image.frombytes(image.mode, image.size, image.tobytes())


def validate_and_canonicalize_logo(data: bytes):
    """Validate uploaded logo bytes and return the canonical form.

    Returns ``(stored_bytes, media_type, width, height)`` where
    ``stored_bytes`` are the canonical re-encode (never the uploaded
    bytes). Raises :class:`BrandingError` with a plain-language reason
    on any failure; a rejection changes nothing stored (the route
    validates before any write — A8(c)).
    """
    if not data:
        raise BrandingError("The logo file is empty.")
    if len(data) > MAX_LOGO_BYTES:
        raise BrandingError("Logo is too large. Logos are at most 512 KB.")
    if data.startswith(_PNG_MAGIC):
        expected = "PNG"
    elif data.startswith(_JPEG_MAGIC):
        expected = "JPEG"
    else:
        raise BrandingError(
            "Logo must be a PNG or JPEG image. Other formats, "
            "including SVG, GIF and WebP, are not accepted.")
    previous_cap = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS_LIMIT
    try:
        # (3)+(4): open, check format/dimensions, verify(), then a
        # fresh open + full load() — any exception is a rejection.
        try:
            with Image.open(io.BytesIO(data)) as probe:
                fmt = probe.format
                width, height = probe.size
                if fmt not in ("PNG", "JPEG") or fmt != expected:
                    raise BrandingError(
                        "Logo must be a PNG or JPEG image.")
                if not (1 <= width <= MAX_LOGO_DIMENSION
                        and 1 <= height <= MAX_LOGO_DIMENSION):
                    raise BrandingError(
                        "Logo dimensions must be between 1x1 and "
                        "2048x2048 pixels.")
                probe.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.load()
                decoded_format = image.format
                if decoded_format != expected:
                    raise BrandingError(
                        "Logo must be a PNG or JPEG image.")
                width, height = image.size
                if not (1 <= width <= MAX_LOGO_DIMENSION
                        and 1 <= height <= MAX_LOGO_DIMENSION):
                    raise BrandingError(
                        "Logo dimensions must be between 1x1 and "
                        "2048x2048 pixels.")
                # (5): canonical re-encode to the SAME format from the
                # decoded pixels, via a metadata-free reconstruction
                # (_metadata_free_image): no inherited chunk/metadata
                # (iCCP, text chunks, EXIF) is carried over, and
                # appended trailing payloads cannot survive re-encoding.
                buffer = io.BytesIO()
                if expected == "PNG":
                    _metadata_free_image(image).save(buffer, format="PNG")
                else:
                    rgb = image if image.mode == "RGB" else \
                        image.convert("RGB")
                    _metadata_free_image(rgb).save(
                        buffer, format="JPEG", quality=95)
        except BrandingError:
            raise
        except Exception:
            raise BrandingError(
                "That logo file could not be decoded as a valid "
                "PNG or JPEG image.")
    finally:
        Image.MAX_IMAGE_PIXELS = previous_cap
    stored = buffer.getvalue()
    if len(stored) > MAX_LOGO_BYTES:
        raise BrandingError("Logo is too large. Logos are at most 512 KB.")
    media_type = "image/png" if expected == "PNG" else "image/jpeg"
    return stored, media_type, width, height


# ---------------------------------------------------------------------------
# Text / accent validation
# ---------------------------------------------------------------------------

def clean_text_field(value, *, label: str, max_chars: int):
    """Trim a plain-text branding field, or reject it.

    Raw input is byte-capped (A8(b)) before this is called by the
    route; here control characters are REJECTED (never silently
    stripped into a different string) and the trimmed length is capped.
    Returns None for an absent/blank value.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise BrandingError(f"{label} must be plain text.")
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise BrandingError(
                f"{label} must not contain control characters.")
    cleaned = value.strip()
    if len(cleaned) > max_chars:
        raise BrandingError(
            f"{label} is too long (at most {max_chars} characters).")
    return cleaned or None


def validate_accent(value):
    """Accent must match ``#rrggbb`` exactly or be rejected (400)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise BrandingError("Accent color must be a hex color like #1a2b3c.")
    cleaned = value.strip()
    if not cleaned:
        return None
    if not _ACCENT_RE.match(cleaned):
        raise BrandingError(
            "Accent color must be a hex color like #1a2b3c.")
    return cleaned.lower()


# ---------------------------------------------------------------------------
# Branding-dict assembly
# ---------------------------------------------------------------------------

def branding_dict_from_row(row, logo_path: str | None = None):
    """Assemble the pdf_export branding dict from a stored row only."""
    if row is None:
        return None
    branding: dict = {}
    if row.business_name:
        branding["business_name"] = row.business_name
    if row.client_name:
        branding["client_name"] = row.client_name
    if row.report_title:
        branding["report_title"] = row.report_title
    if row.accent:
        branding["accent"] = row.accent
    if logo_path:
        branding["logo_path"] = logo_path
        if row.logo_width:
            branding["logo_width"] = row.logo_width
        if row.logo_height:
            branding["logo_height"] = row.logo_height
    return branding


@contextmanager
def branding_dict_with_temp_logo(row):
    """Yield the branding dict for ``row``, materialising stored logo
    bytes to a server-owned temp file for the render (A8(f)).

    The temp file is created with ``delete=False`` under the system
    temp dir and unlinked in a ``finally`` on every path, success or
    failure. With no row / no logo, yields the plain dict (or None).
    """
    if row is None or not row.logo_bytes:
        yield branding_dict_from_row(row)
        return
    suffix = ".png" if row.logo_media_type == "image/png" else ".jpg"
    handle = tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, prefix="stacksift-branding-")
    try:
        handle.write(row.logo_bytes)
        handle.close()
        yield branding_dict_from_row(row, logo_path=handle.name)
    finally:
        try:
            handle.close()
        except Exception:
            pass
        Path(handle.name).unlink(missing_ok=True)


def web_branding_from_row(row, result_id):
    """Template context for the owned report's branded header band."""
    if row is None:
        return None
    return {
        "business_name": row.business_name,
        "client_name": row.client_name,
        "report_title": row.report_title,
        "accent": row.accent,
        "logo_url": (f"/reports/{result_id}/branding/logo"
                     if row.logo_bytes else None),
    }


def logo_sha256(stored_bytes: bytes) -> str:
    return hashlib.sha256(stored_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Sample constant profile (Decision 8 as amended by A5)
#
# The sample has no Result and no owner, so it does NOT go through the
# owner machinery: the profile below is a server-side constant. The
# logo is the genuine WellInstance site favicon, shipped as a static
# asset in this repo (app/static/wellinstance-icon.svg, with a faithful
# librsvg-rendered PNG conversion alongside it for the PDF — SVG is
# never fed to the PDF renderer). The PDF report_title remains the
# existing SAMPLE label; the web sample shows this brand header with
# the existing SAMPLE banner.
# ---------------------------------------------------------------------------

SAMPLE_BUSINESS_NAME = "WellInstance"
SAMPLE_ACCENT = "#d4af37"
SAMPLE_REPORT_TITLE = "SAMPLE \u2014 StackSift Analysis Report"
SAMPLE_LOGO_PNG_PATH = _STATIC_DIR / "wellinstance-icon.png"
SAMPLE_LOGO_SVG_URL = "/static/wellinstance-icon.svg"
# Pixel dimensions of the shipped PNG conversion (256x256 render of
# the 64x64-viewBox SVG).
SAMPLE_LOGO_WIDTH = 256
SAMPLE_LOGO_HEIGHT = 256


def sample_branding_dict() -> dict:
    """Constant branding dict for the sample PDF."""
    return {
        "business_name": SAMPLE_BUSINESS_NAME,
        "accent": SAMPLE_ACCENT,
        "report_title": SAMPLE_REPORT_TITLE,
        "logo_path": str(SAMPLE_LOGO_PNG_PATH),
        "logo_width": SAMPLE_LOGO_WIDTH,
        "logo_height": SAMPLE_LOGO_HEIGHT,
    }


def sample_web_branding() -> dict:
    """Template context for the sample page's brand header."""
    return {
        "business_name": SAMPLE_BUSINESS_NAME,
        "client_name": None,
        "report_title": None,
        "accent": SAMPLE_ACCENT,
        "logo_url": SAMPLE_LOGO_SVG_URL,
    }
