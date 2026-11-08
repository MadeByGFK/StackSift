"""Issue #163: M2 branded client reports (spec v1 + amendments A1-A9).

Teeth discipline: new-feature assertions FAIL on the pre-build tree
(1a2f84c6 — no report_branding table, no branding routes, header_block
places logos at h=10 with NO width bound, sample branding is
title-only); regression gates are labelled in their docstrings.
"""

import hashlib
import io
import json
import re
import struct
import tempfile
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from PIL import Image

from test_account_migrations import migrated_engine  # noqa: F401
from test_issue159_sample import cold_cache, sample_client  # noqa: F401
from test_issue162_brief import _pdf_text, _sample_artifact
from test_issue160_designed_reports import extract_pdf_text
from test_phase2b_reports_pdf import _login, _signup_and_verify
from test_structured_export_e2e import _custom_result, _session_csrf, _setup
try:
    from app import branding as B
except ImportError:  # pre-build tree: per-test failures, not a lone
    B = None         # collection error (teeth discipline)
from app.pdf_export import FOOTER_TEXT, generate_deep_dive_pdf

FOOTER = FOOTER_TEXT


# --- helpers -----------------------------------------------------------------

def _png(w=64, h=32, color=(200, 30, 30), mode="RGB"):
    buf = io.BytesIO()
    Image.new(mode, (w, h), color).save(buf, format="PNG")
    return buf.getvalue()


def _jpeg(w=64, h=32, color=(30, 30, 200)):
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format="JPEG")
    return buf.getvalue()


def _gif():
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (0, 0, 0)).save(buf, format="GIF")
    return buf.getvalue()


def _truncated_jpeg_after_sos():
    data = _jpeg(32, 32)
    sos = data.index(b"\xff\xda")
    return data[:sos + 12]  # cut inside/just after the SOS segment


def _crc_corrupt_png():
    data = bytearray(_png(32, 32))
    idat = data.index(b"IDAT")
    data[idat + 12] ^= 0xFF  # flip a byte inside IDAT data
    return bytes(data)


def _huge_header_png():
    """A tiny file whose IHDR claims 5000x5000 (pixel count >> cap)."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 5000, 5000, 8, 2, 0, 0, 0)
    crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    return sig + struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data \
        + struct.pack(">I", crc)


def _make_deep_dive(auth_env):
    """Owner + source report + generated deep_dive Result id.

    PREMISE CHANGED (#164 Phase A, A10: dollar-product): the owned
    deep-dive fixture is now a DOLLAR-paid report — a seeded $9
    entitlement is redeemed by the POST (branding is included with
    paid reports on the same terms; the Phase A suite separately
    proves branding on the dollar path end-to-end)."""
    email, user_id, rid, csrf = _setup(auth_env)
    from product_seed import seed_entitlement_for_source
    seed_entitlement_for_source(auth_env.sessions, rid)
    gen = auth_env.client.post(f"/reports/{rid}/deep-dive",
                               data={"csrf_token": csrf})
    assert gen.status_code == 200, gen.text[:300]
    return email, user_id, rid, gen.json()["analysis_result_id"], csrf


def _post_branding(auth_env, dd_id, csrf, data=None, logo=None,
                   logo_name="logo.png", logo_type="image/png"):
    fields = {"csrf_token": csrf}
    fields.update(data or {})
    files = None
    if logo is not None:
        files = {"logo": (logo_name, logo, logo_type)}
    return auth_env.client.post(
        f"/reports/{dd_id}/branding", data=fields, files=files)


def _branding_row(auth_env, dd_id):
    from app import models
    db = auth_env.sessions()
    try:
        return db.query(models.ReportBranding).filter(
            models.ReportBranding.result_id == uuid.UUID(str(dd_id))
        ).first()
    finally:
        db.close()


def _row_snapshot(auth_env, dd_id):
    row = _branding_row(auth_env, dd_id)
    if row is None:
        return None
    return (row.business_name, row.client_name, row.report_title,
            row.accent, row.logo_bytes, row.logo_media_type,
            row.logo_sha256, row.logo_width, row.logo_height)


def _counts(auth_env, user_id):
    from app import models
    db = auth_env.sessions()
    try:
        return {
            "operations": db.query(models.Operation).filter(
                models.Operation.user_id == user_id).count(),
            "consents": db.query(models.Consent).filter(
                models.Consent.user_id == user_id).count(),
            "ledger": db.query(models.CreditLedger).filter(
                models.CreditLedger.user_id == user_id).count(),
        }
    finally:
        db.close()


def _image_placements_mm(pdf_bytes):
    """(width_mm, height_mm) for every image XObject placement."""
    out = []
    for m in re.finditer(rb"stream\r?\n(.*)\r?\nendstream", pdf_bytes,
                         re.DOTALL):
        raw = m.group(1)
        try:
            dec = zlib.decompress(raw)
        except zlib.error:
            dec = raw
        for w, h in re.findall(
                rb"q ([\d.]+) 0 0 ([\d.]+) [\d.]+ [\d.]+ cm /I\d+ Do", dec):
            out.append((float(w) * 25.4 / 72.0, float(h) * 25.4 / 72.0))
    return out


def _page_count(pdf_bytes):
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf_bytes))


def _normalized_body(pdf_bytes, drop_tokens):
    """A6 integrity oracle: extracted text with header/footer/
    timestamp furniture stripped, whitespace-normalized."""
    text = extract_pdf_text(pdf_bytes)
    kept = []
    prev_was_footer = False
    for line in text.splitlines():
        if FOOTER in line:
            prev_was_footer = True
            continue
        if prev_was_footer and line.strip().isdigit():
            # The footer's total-page count extracts as its own line.
            prev_was_footer = False
            continue
        prev_was_footer = False
        if any(tok in line for tok in drop_tokens):
            continue
        if "Generated:" in line or "File:" in line:
            continue
        # Pagination furniture (A6): a block split across a page break
        # resumes under a "(continued)" label; where the break falls
        # legitimately shifts when the header grows, so the label is
        # furniture, not body content.
        if "(continued)" in line:
            continue
        kept.append(line)
    return re.sub(r"\s+", " ", " ".join(kept)).strip()


# --- A1: logo validation (unit) ----------------------------------------------

def test_a1_valid_png_and_jpeg_accepted_and_canonical():
    for data, media in ((_png(), "image/png"), (_jpeg(), "image/jpeg")):
        stored, mt, w, h = B.validate_and_canonicalize_logo(data)
        assert mt == media and (w, h) == (64, 32)
        with Image.open(io.BytesIO(stored)) as im:
            im.load()
            assert im.format == ("PNG" if media == "image/png" else "JPEG")


def test_a1_appended_script_never_survives_reencode():
    poisoned = _jpeg() + b"<script>alert(1)</script>"
    stored, mt, _w, _h = B.validate_and_canonicalize_logo(poisoned)
    assert mt == "image/jpeg"
    assert stored != poisoned
    assert b"<script>" not in stored and b"alert(1)" not in stored


@pytest.mark.parametrize("bad", [
    _truncated_jpeg_after_sos(),          # SOS-cut truncated JPEG
    _crc_corrupt_png(),                   # CRC-corrupt PNG
    _huge_header_png(),                   # header claims > cap pixels
    b"\x89PNG\r\n\x1a\n" + b"not-a-png",  # PNG magic, corrupt body
    _gif(),                               # GIF rejected outright
    b"<svg xmlns='http://www.w3.org/2000/svg'></svg>",  # SVG rejected
    b"plain text renamed to png",         # text file
    b"",                                  # empty
    _png(2049, 1),                        # dimension > 2048
    _png(1, 2049),
])
def test_a1_validation_rejects_matrix(bad):
    with pytest.raises(B.BrandingError):
        B.validate_and_canonicalize_logo(bad)


def test_a1_validation_rejects_oversize_bytes():
    with pytest.raises(B.BrandingError):
        B.validate_and_canonicalize_logo(_png() + b"A" * (513 * 1024))


def test_a1_corrupt_idat_png_rejected():
    data = bytearray(_png(48, 48))
    idat = data.index(b"IDAT")
    # Corrupt the zlib stream inside IDAT (beyond the CRC flip above).
    data[idat + 6] ^= 0xFF
    with pytest.raises(B.BrandingError):
        B.validate_and_canonicalize_logo(bytes(data))


# --- routes: happy path, web view, PDF ---------------------------------------

def test_branding_post_owner_sets_row_and_web_view(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = _post_branding(auth_env, dd_id, csrf, data={
        "business_name": "Acme Consulting",
        "client_name": "Globex",
        "report_title": "Q3 Incident Review",
        "accent": "#123456",
    }, logo=_png())
    assert r.status_code == 200, r.text[:300]
    snap = _row_snapshot(auth_env, dd_id)
    assert snap[0:4] == ("Acme Consulting", "Globex",
                         "Q3 Incident Review", "#123456")
    assert snap[5] == "image/png" and snap[4]
    # Stored bytes are the canonical re-encode, sha over stored bytes.
    assert snap[6] == hashlib.sha256(snap[4]).hexdigest()
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert page.status_code == 200
    assert "Acme Consulting" in page.text
    assert "Prepared for: Globex" in page.text
    assert "Q3 Incident Review" in page.text
    assert "--accent: #123456" in page.text
    assert f"/reports/{dd_id}/branding/logo" in page.text
    # Panel copy (A3): applies to every PDF generated after it is set.
    assert "Branding applies to every PDF generated after it is set" \
        in page.text


def test_branding_pdf_admitted_and_unlocked_paths_and_footer(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf, data={
        "business_name": "Acme Consulting", "client_name": "Globex",
        "report_title": "Q3 Incident Review", "accent": "#123456"})
    # Admitted path (first export charges the unlock).
    first = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                 data={"csrf_token": csrf})
    assert first.status_code == 200 and first.content[:4] == b"%PDF"
    # Unlocked path (no stored replay exists yet for a fresh admit?
    # the admitted path stores one — this second POST exercises the
    # A3 skip-replay -> unlocked fresh-generation path).
    second = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                  data={"csrf_token": csrf})
    assert second.status_code == 200
    for blob in (first.content, second.content):
        text = _pdf_text(blob)
        assert "Acme Consulting" in text
        assert "Prepared for: Globex" in text
        assert "Q3 Incident Review" in text
        # FOOTER_TEXT unchanged on every page.
        assert extract_pdf_text(blob).count(FOOTER) == _page_count(blob)


def test_branding_integrity_normalized_body_identical(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    plain = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                 data={"csrf_token": csrf})
    assert plain.status_code == 200
    _post_branding(auth_env, dd_id, csrf, data={
        "business_name": "Acme Consulting", "client_name": "Globex",
        "report_title": "Q3 Incident Review", "accent": "#123456"},
        logo=_png())
    branded = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                   data={"csrf_token": csrf})
    assert branded.status_code == 200
    # Header furniture dropped on BOTH sides: the branded lines and
    # the unbranded default title they replace.
    drops = ("Acme Consulting", "Prepared for:", "Q3 Incident Review",
             "StackSift Analysis Report")
    assert _normalized_body(plain.content, drops) == \
        _normalized_body(branded.content, drops)
    btext = _pdf_text(branded.content)
    assert "Limitations" in btext
    # Redaction integrity on an artifact that DOES carry redactions
    # (the #159/#162 sample artifact): branded and unbranded renders
    # both keep every [REDACTED] notice, byte-identical in the text.
    artifact = json.dumps(_sample_artifact())
    plain_sample = generate_deep_dive_pdf(artifact, "sample.log")
    branded_sample = generate_deep_dive_pdf(
        artifact, "sample.log",
        branding={"business_name": "Acme Consulting",
                  "client_name": "Globex",
                  "report_title": "Q3 Incident Review"})
    assert _pdf_text(plain_sample).count("[REDACTED]") > 0
    assert _pdf_text(branded_sample).count("[REDACTED]") == \
        _pdf_text(plain_sample).count("[REDACTED]")


def test_branding_smuggled_fixed_tokens_ignored(auth_env):
    from app.pdf_export import resolve_tokens
    tok = resolve_tokens({"accent": "#123456", "severity": "#000000",
                          "limitation": "#000000", "redaction": "#000000",
                          "navy": "#000000"})
    from app.pdf_export import BRAND
    assert tok.severity == BRAND["severity"]
    assert tok.limitation == BRAND["limitation"]
    assert tok.redaction == BRAND["redaction"]
    assert tok.navy == BRAND["navy"]
    # Route level: extra form fields are not read into the row at all.
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = _post_branding(auth_env, dd_id, csrf, data={
        "business_name": "Acme", "severity": "#000000",
        "redaction": "#000000"})
    assert r.status_code == 200
    assert _row_snapshot(auth_env, dd_id)[0] == "Acme"


# --- routes: logo validation matrix -------------------------------------------

@pytest.mark.parametrize("logo,name,ctype", [
    (b"<svg xmlns='x'></svg>", "logo.svg", "image/svg+xml"),
    (_gif(), "logo.gif", "image/gif"),
    (b"hello, not an image", "logo.png", "image/png"),
    (b"\x89PNG\r\n\x1a\n" + b"junk", "logo.png", "image/png"),
    (_png(2049, 4), "logo.png", "image/png"),
    (_png() + b"A" * (513 * 1024), "logo.png", "image/png"),
    (_truncated_jpeg_after_sos(), "logo.jpg", "image/jpeg"),
    (_crc_corrupt_png(), "logo.png", "image/png"),
])
def test_branding_logo_matrix_rejected_nothing_stored(
        auth_env, logo, name, ctype):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "Acme"},
                       logo=logo, logo_name=name, logo_type=ctype)
    assert r.status_code == 400, r.text[:200]
    assert _branding_row(auth_env, dd_id) is None


def test_branding_spoofed_content_type_does_not_rescue(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = _post_branding(auth_env, dd_id, csrf, logo=b"definitely text",
                       logo_name="logo.png", logo_type="image/png")
    assert r.status_code == 400
    # ...and a real PNG mislabelled as text still validates by content.
    r = _post_branding(auth_env, dd_id, csrf, logo=_png(),
                       logo_name="logo.png", logo_type="text/plain")
    assert r.status_code == 200


def test_branding_empty_file_part_keeps_existing_logo(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    assert _post_branding(auth_env, dd_id, csrf, logo=_png()
                          ).status_code == 200
    before = _row_snapshot(auth_env, dd_id)
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "Renamed"},
                       logo=b"", logo_name="", logo_type="")
    assert r.status_code == 200
    after = _row_snapshot(auth_env, dd_id)
    assert after[0] == "Renamed"
    assert after[4] == before[4]  # logo kept byte-for-byte


def test_branding_remove_logo_field_clears_only_logo(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "Acme", "remove_logo": "1"})
    assert r.status_code == 200
    snap = _row_snapshot(auth_env, dd_id)
    assert snap[0] == "Acme" and snap[4] is None and snap[5] is None


def test_branding_unexpected_file_part_400(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = auth_env.client.post(
        f"/reports/{dd_id}/branding",
        data={"csrf_token": csrf, "business_name": "Acme"},
        files={"evil": ("e.png", _png(), "image/png")})
    assert r.status_code == 400
    assert _branding_row(auth_env, dd_id) is None


def test_branding_declared_oversize_413_middleware(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    big = _png() + b"A" * (1100 * 1024)  # declared length > 1 MiB
    r = _post_branding(auth_env, dd_id, csrf, logo=big)
    assert r.status_code == 413
    assert _branding_row(auth_env, dd_id) is None


def test_branding_text_rules(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    for data in ({"business_name": "x" * 81},
                 {"client_name": "y" * 81},
                 {"report_title": "z" * 121},
                 {"business_name": "Acme\x01Corp"},
                 {"accent": "red"}, {"accent": "#fff"},
                 {"accent": "#rrggbb;}</style><script>"},
                 {"accent": "#12345"}, {"accent": "#1234567"}):
        r = _post_branding(auth_env, dd_id, csrf, data=data)
        assert r.status_code == 400, (data, r.status_code)
    assert _branding_row(auth_env, dd_id) is None
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "  Padded Name  "})
    assert r.status_code == 200
    assert _row_snapshot(auth_env, dd_id)[0] == "Padded Name"


def test_branding_html_payloads_escaped_web_and_literal_pdf(auth_env):
    payload = '<script>alert("x")</script>'
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": payload})
    assert r.status_code == 200
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert payload not in page.text
    assert "&lt;script&gt;" in page.text
    pdf = auth_env.client.post(f"/reports/{dd_id}/pdf",
                               data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert '<script>alert("x")</script>' in _pdf_text(pdf.content)


# --- A8(c): atomicity -----------------------------------------------------------

def test_a8_invalid_replacement_leaves_prior_row_untouched(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Original Co",
                         "accent": "#112233"}, logo=_png())
    before = _row_snapshot(auth_env, dd_id)
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "Replacement Co"},
                       logo=_gif(), logo_name="x.gif",
                       logo_type="image/gif")
    assert r.status_code == 400
    assert _row_snapshot(auth_env, dd_id) == before


def test_a8_temp_files_unlinked_on_success_and_failure(auth_env,
                                                       monkeypatch):
    from app import pdf_export as pdf_mod
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    # Unlock first (admitted path also renders with the temp logo).
    ok = auth_env.client.post(f"/reports/{dd_id}/pdf",
                              data={"csrf_token": csrf})
    assert ok.status_code == 200
    tmpdir = Path(tempfile.gettempdir())
    before = set(tmpdir.glob("stacksift-branding-*"))
    ok2 = auth_env.client.post(f"/reports/{dd_id}/pdf",
                               data={"csrf_token": csrf})
    assert ok2.status_code == 200
    assert set(tmpdir.glob("stacksift-branding-*")) == before

    def _boom(*a, **k):
        raise RuntimeError("forced generation failure")
    monkeypatch.setattr(pdf_mod, "generate_deep_dive_pdf", _boom)
    fail = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                data={"csrf_token": csrf})
    assert fail.status_code == 500
    assert set(tmpdir.glob("stacksift-branding-*")) == before


# --- security / ownership --------------------------------------------------------

def test_branding_security_ownership_and_logo_route(auth_env):
    _email, user_id, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    # CSRF missing -> 403.
    r = auth_env.client.post(f"/reports/{dd_id}/branding",
                             data={"business_name": "Nope"})
    assert r.status_code == 403
    logo = auth_env.client.get(f"/reports/{dd_id}/branding/logo")
    assert logo.status_code == 200
    assert logo.headers["content-type"].startswith("image/png")
    assert logo.headers["x-content-type-options"] == "nosniff"
    assert logo.headers["cache-control"] == "private, no-store"
    assert logo.content == _row_snapshot(auth_env, dd_id)[4]
    # Non-owner: POST -> 404, logo GET -> 404.
    email_b, _uid_b = _signup_and_verify(auth_env)
    _login(auth_env, email_b)
    csrf_b = _session_csrf(auth_env)
    r = _post_branding(auth_env, dd_id, csrf_b,
                       data={"business_name": "Hijack"})
    assert r.status_code == 404
    assert auth_env.client.get(
        f"/reports/{dd_id}/branding/logo").status_code == 404


def test_branding_anonymous_401(auth_env):
    from fastapi.testclient import TestClient
    from app.main import app
    _email, _uid, _rid, dd_id, _csrf = _make_deep_dive(auth_env)
    with TestClient(app, base_url="https://testserver",
                    raise_server_exceptions=False) as anon:
        assert anon.post(f"/reports/{dd_id}/branding",
                         data={"business_name": "X"}).status_code == 401
        assert anon.get(
            f"/reports/{dd_id}/branding/logo").status_code == 401


def test_branding_text_never_logged(auth_env, caplog):
    import logging
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    with caplog.at_level(logging.DEBUG):
        _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "LogProbeBizXYZ"},
                       logo=_png())
        auth_env.client.get(f"/reports/{dd_id}/branding/logo")
    assert "LogProbeBizXYZ" not in caplog.text


# --- no-charge / identity ---------------------------------------------------------

def test_branding_no_charge_rows_and_replay_free(auth_env):
    _email, user_id, rid, dd_id, csrf = _make_deep_dive(auth_env)
    before = _counts(auth_env, user_id)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme 2"})
    auth_env.client.post(f"/reports/{dd_id}/branding/clear",
                         data={"csrf_token": csrf})
    auth_env.client.get(f"/reports/{dd_id}/branding/logo")
    assert _counts(auth_env, user_id) == before
    # Deep-dive replay identity unchanged: re-requesting the Analysis
    # Report after branding still replays free (no new operation).
    replay = auth_env.client.post(f"/reports/{rid}/deep-dive",
                                  data={"csrf_token": csrf})
    assert replay.status_code == 200 and replay.json()["replayed"] is True
    assert _counts(auth_env, user_id) == before


# --- lifecycle (A2) -----------------------------------------------------------------

def test_branding_on_standard_report_422(auth_env):
    _email, _uid, rid, csrf = _setup(auth_env)
    r = _post_branding(auth_env, rid, csrf, data={"business_name": "A"})
    assert r.status_code == 422


def test_branding_on_expired_report_410(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _expire(auth_env, dd_id)
    r = _post_branding(auth_env, dd_id, csrf, data={"business_name": "A"})
    assert r.status_code == 410


def _expire(auth_env, result_id, *, deleted=False):
    from app import models
    db = auth_env.sessions()
    try:
        row = db.get(models.Result, uuid.UUID(str(result_id)))
        row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        if deleted:
            row.deleted_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def test_a2_cleanup_expiry_removes_row_and_bytes(auth_env):
    from app import credit_maintenance
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    assert _branding_row(auth_env, dd_id) is not None
    _expire(auth_env, dd_id)
    db = auth_env.sessions()
    try:
        credit_maintenance.cleanup_results(db)
    finally:
        db.close()
    assert _branding_row(auth_env, dd_id) is None


def test_a2_cleanup_sweeps_already_soft_deleted(auth_env):
    from app import credit_maintenance
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    # Soft-delete WITHOUT expiring (another path's delete): the sweep
    # on a later cleanup run removes the branding row.
    from app import models
    db = auth_env.sessions()
    try:
        row = db.get(models.Result, uuid.UUID(str(dd_id)))
        row.deleted_at = datetime.now(timezone.utc)
        db.commit()
        credit_maintenance.cleanup_results(db)
    finally:
        db.close()
    assert _branding_row(auth_env, dd_id) is None


def test_a2_physical_delete_cascades(auth_env):
    """FK ON DELETE CASCADE covers physical deletes (A2): a Result
    with no operation graph (so the delete itself is legal) takes its
    branding row with it."""
    from app import models
    _email, user_id, _rid, _csrf = _setup(auth_env)
    dd_id = _custom_result(auth_env, user_id, {"filename": "x.log"},
                           report_type="deep_dive")
    db = auth_env.sessions()
    try:
        db.add(models.ReportBranding(
            result_id=dd_id, business_name="Acme",
            logo_bytes=_png(), logo_media_type="image/png"))
        db.commit()
        assert db.query(models.ReportBranding).filter(
            models.ReportBranding.result_id == dd_id).count() == 1
        result = db.get(models.Result, dd_id)
        db.delete(result)
        db.commit()
        assert db.query(models.ReportBranding).filter(
            models.ReportBranding.result_id == dd_id).count() == 0
    finally:
        db.close()


def test_a2_upload_after_cleanup_rejected_410_no_resurrection(auth_env):
    from app import credit_maintenance
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    _expire(auth_env, dd_id)
    db = auth_env.sessions()
    try:
        credit_maintenance.cleanup_results(db)
    finally:
        db.close()
    assert _branding_row(auth_env, dd_id) is None
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "Zombie"}, logo=_png())
    assert r.status_code == 410
    assert _branding_row(auth_env, dd_id) is None


def test_clear_retains_cleared_state_row_and_unbrands(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    row_before = _branding_row(auth_env, dd_id)
    created_at, row_id = row_before.created_at, row_before.id
    r = auth_env.client.post(f"/reports/{dd_id}/branding/clear",
                             data={"csrf_token": csrf})
    assert r.status_code == 200
    row = _branding_row(auth_env, dd_id)
    assert row is not None and row.id == row_id  # retained, not deleted
    assert row.business_name is None and row.logo_bytes is None
    assert row.accent is None and row.report_title is None
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert "Acme" not in page.text


# --- A3: stored-PDF replay policy -----------------------------------------------------

def test_a3_pdf_first_set_then_clear(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    # PDF-first: first export stores a PDF; second serves the replay.
    first = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                 data={"csrf_token": csrf})
    assert first.status_code == 200
    replay = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                  data={"csrf_token": csrf})
    assert replay.content == first.content  # stored replay, byte-exact
    assert "Acme Consulting" not in _pdf_text(replay.content)
    # Set branding -> next PDF is freshly generated WITH branding.
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme Consulting"})
    branded = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                   data={"csrf_token": csrf})
    assert "Acme Consulting" in _pdf_text(branded.content)
    # Clear -> next PDF is freshly generated unbranded.
    auth_env.client.post(f"/reports/{dd_id}/branding/clear",
                         data={"csrf_token": csrf})
    cleared = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                   data={"csrf_token": csrf})
    assert "Acme Consulting" not in _pdf_text(cleared.content)


def test_a3_csv_first_unlock_then_branded_pdf(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    csv = auth_env.client.post(f"/reports/{dd_id}/exports/csv",
                               data={"csrf_token": csrf})
    assert csv.status_code == 200, csv.text[:200]
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Csv First Co"})
    pdf = auth_env.client.post(f"/reports/{dd_id}/pdf",
                               data={"csrf_token": csrf})
    assert pdf.status_code == 200
    assert "Csv First Co" in _pdf_text(pdf.content)


def test_a3_no_branding_ever_keeps_stored_replay(auth_env):
    """Regression gate: a report that never had branding keeps its
    unbranded PDF body identical across repeated exports.

    PREMISE CHANGED (#164, A9(d)): the fixture artifact is now
    dollar-paid, and product PDFs are generated on the fly (no
    stored derivative), so raw bytes legitimately differ by the
    embedded generation timestamp — the legacy stored-replay
    byte-identity premise belongs to credit-era artifacts. The
    invariant this gate protects is preserved in its dollar form:
    the normalized body (timestamps/footer furniture stripped) is
    identical across both renders."""
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    first = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                 data={"csrf_token": csrf})
    second = auth_env.client.post(f"/reports/{dd_id}/pdf",
                                  data={"csrf_token": csrf})
    assert first.status_code == second.status_code == 200
    assert first.content[:4] == second.content[:4] == b"%PDF"
    assert _normalized_body(second.content, []) == \
        _normalized_body(first.content, [])


# --- A4: deep-dive sharing stays unsupported -------------------------------------------

def test_a4_deep_dive_share_still_unsupported_branded_or_not(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    for branded in (False, True):
        if branded:
            _post_branding(auth_env, dd_id, csrf,
                           data={"business_name": "Acme"})
        r = auth_env.client.post(
            f"/reports/{dd_id}/share",
            data={"csrf_token": csrf,
                  "idempotency_key": f"a4-{branded}", "format": "pdf"})
        # Exactly the base-tree behaviour: the share owner gate only
        # resolves analysis-type reports, so a deep_dive id is a 404
        # here and shared serving stays unavailable (A4's negative
        # case); no link row is created.
        assert r.status_code == 404, r.text[:200]
    from app import models
    db = auth_env.sessions()
    try:
        assert db.query(models.ReportSharing).filter(
            models.ReportSharing.result_id == uuid.UUID(str(dd_id))
        ).count() == 0
    finally:
        db.close()


# --- A6: geometry -----------------------------------------------------------------------

@pytest.mark.parametrize("w,h", [(2048, 1), (1, 2048), (512, 512)])
def test_a6_pdf_logo_contain_fit_geometry(w, h):
    logo = f"/tmp/issue163-geo-{w}x{h}.png"
    Path(logo).write_bytes(_png(w, h))
    artifact = json.dumps(_sample_artifact())
    blob = generate_deep_dive_pdf(
        artifact, "geo.log",
        branding={"business_name": "Geo Co", "logo_path": logo,
                  "logo_width": w, "logo_height": h})
    placements = _image_placements_mm(blob)
    assert placements, "logo image must be placed"
    for img_w, img_h in placements:
        assert img_w <= 40.0 + 0.5 and img_h <= 10.0 + 0.5
        assert img_w > 0 and img_h > 0
    # Aspect preserved (fpdf rounds placements to 2 decimal places,
    # which dominates the ratio error at the extreme aspects — at
    # 1x2048 the placed width is ~0.005mm, below stream precision, so
    # there the bound itself is the assertion).
    img_w, img_h = placements[0]
    if min(img_w, img_h) >= 0.5:
        assert abs((img_w / img_h) - (w / h)) / (w / h) < 0.15
    else:
        assert max(img_w, img_h) <= 40.0 + 0.5
        assert min(img_w, img_h) < 0.5


def test_a6_transparent_png_and_long_strings_multipage():
    logo = "/tmp/issue163-geo-transparent.png"
    Path(logo).write_bytes(_png(200, 100, color=(10, 20, 30, 0),
                                mode="RGBA"))
    artifact = json.dumps(_sample_artifact())
    blob = generate_deep_dive_pdf(
        artifact, "long.log",
        branding={
            "business_name": "A Very Long Business Name With Many "
                             "Words That Must Wrap Cleanly In Header",
            "client_name": "A Very Long Client Name Also Wrapping "
                           "Across The Designed Header Block Area",
            "report_title": "An Extremely Long Report Title That "
                            "Wraps Over Multiple Lines In The Header",
            "logo_path": logo, "logo_width": 200, "logo_height": 100})
    text = _pdf_text(blob)
    assert "Very Long Business Name" in text
    assert "Very Long Client Name" in text
    assert _page_count(blob) >= 2  # multi-page Brief artifact
    assert extract_pdf_text(blob).count(FOOTER) == _page_count(blob)


def test_a6_render_failure_never_fails_export(caplog):
    import logging
    artifact = json.dumps(_sample_artifact())
    with caplog.at_level(logging.WARNING):
        blob = generate_deep_dive_pdf(
            artifact, "badlogo.log",
            branding={"business_name": "Visible Name Co",
                      "logo_path": "/tmp/does-not-exist-163.png",
                      "logo_width": 10, "logo_height": 10})
    assert blob[:4] == b"%PDF"
    # Nonexistent path is skipped silently (existing behaviour); now
    # force a REAL render failure: a file that exists but is not an
    # image at all.
    Path("/tmp/not-an-image-163.png").write_bytes(b"not an image")
    with caplog.at_level(logging.WARNING):
        blob = generate_deep_dive_pdf(
            artifact, "badlogo2.log",
            branding={"business_name": "Visible Name Co",
                      "logo_path": "/tmp/not-an-image-163.png",
                      "logo_width": 10, "logo_height": 10})
    assert blob[:4] == b"%PDF"
    assert "Visible Name Co" in _pdf_text(blob)
    assert "Visible Name Co" not in caplog.text  # warning logs no text


# --- stale UI -----------------------------------------------------------------------------

def test_stale_ui_fresh_page_reflects_set_and_clear(auth_env):
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Fresh State Co"})
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert 'value="Fresh State Co"' in page.text
    auth_env.client.post(f"/reports/{dd_id}/branding/clear",
                         data={"csrf_token": csrf})
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert "Fresh State Co" not in page.text


# --- sample (Decision 8 / A5) --------------------------------------------------------------

def test_sample_web_shows_wellinstance_brand_header(sample_client):
    r = sample_client.get("/sample-report")
    assert r.status_code == 200
    assert "WellInstance" in r.text
    assert "/static/wellinstance-icon.svg" in r.text
    assert "SAMPLE" in r.text  # existing SAMPLE banner retained
    assert "<form" not in r.text.lower()  # A5: no form on sample page


def test_sample_pdf_carries_wellinstance_and_sample_label(sample_client):
    r = sample_client.get("/sample-report/pdf")
    assert r.status_code == 200
    text = _pdf_text(r.content)
    assert "WellInstance" in text
    assert "SAMPLE" in text
    assert extract_pdf_text(r.content).count(FOOTER) >= 1
    placements = _image_placements_mm(r.content)
    assert placements  # the logo image is placed in the sample PDF


def test_sample_asset_provenance_and_png_conversion():
    static = Path(__file__).resolve().parents[1] / "app" / "static"
    svg = static / "wellinstance-icon.svg"
    assert hashlib.sha256(svg.read_bytes()).hexdigest() == \
        "2c7bdae0671096001a172d738991299e36fb4e1a91b3191a3dad46d6216fd463"
    png = static / "wellinstance-icon.png"
    with Image.open(png) as im:
        assert im.format == "PNG" and im.size == (256, 256)
        px = im.convert("RGB")
        # Navy tile + white W + gold period survive the conversion.
        assert px.getpixel((128, 20)) == (13, 31, 60)
        colors = px.getcolors(256 * 256)
        color_set = {c for _n, c in colors}
        assert (255, 255, 255) in color_set
        assert (212, 175, 55) in color_set


def test_sample_route_accepts_no_branding_input(sample_client):
    r = sample_client.get(
        "/sample-report?business_name=EvilCorp&accent=%23000000")
    assert r.status_code == 200
    assert "WellInstance" in r.text
    assert "EvilCorp" not in r.text


def test_unbranded_owned_page_and_pdf_unchanged(auth_env):
    """Regression gate (A7): an owned report with NO branding renders
    the report body unchanged and gains ONLY the branding form in the
    Actions area (the named sanctioned premise change)."""
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert page.status_code == 200
    assert "brand-header" not in page.text
    assert "--accent:" not in page.text.split("branding-panel")[0]
    assert f'action="/reports/{dd_id}/branding"' in page.text
    pdf = auth_env.client.post(f"/reports/{dd_id}/pdf",
                               data={"csrf_token": csrf})
    assert "Prepared for:" not in _pdf_text(pdf.content)


# --- Remediation round: Codex review of PR #169 head 5aaa150b ---------------
# All four tests below FAIL on head 5aaa150b (teeth) and pass on the
# remediated head. Findings verified by Sunny, disposition comment on
# PR #169 (comment 6711987636).

def _iccp_profile(data):
    """Decompressed iCCP profile bytes of a PNG, or None."""
    i = 8
    while i + 8 <= len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        typ = data[i + 4:i + 8]
        chunk = data[i + 8:i + 8 + ln]
        if typ == b"iCCP":
            nul = chunk.index(b"\x00")
            return zlib.decompress(chunk[nul + 2:])
        i += 12 + ln
    return None


def _png_with_icc(payload=b"ATTACKER-ICC-PAYLOAD-0123456789"):
    img = Image.new("RGB", (16, 16), (10, 20, 30))
    img.info["icc_profile"] = payload
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_remed_png_icc_profile_stripped_by_reencode():
    """Codex P2 (4503408262): inherited PNG metadata (iCCP) must NOT
    survive the A1 canonical re-encode; pixels must."""
    data = _png_with_icc()
    assert _iccp_profile(data) is not None  # fixture really is poisoned
    stored, media, w, h = B.validate_and_canonicalize_logo(data)
    assert media == "image/png" and (w, h) == (16, 16)
    assert _iccp_profile(stored) is None
    px = Image.open(io.BytesIO(stored)).convert("RGB").getpixel((0, 0))
    assert px == (10, 20, 30)


def test_remed_rgba_alpha_preserved_after_metadata_strip():
    """The metadata-free reconstruction must keep alpha semantics."""
    img = Image.new("RGBA", (8, 8), (200, 100, 50, 128))
    img.info["icc_profile"] = b"X" * 64
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    stored, media, w, h = B.validate_and_canonicalize_logo(buf.getvalue())
    out = Image.open(io.BytesIO(stored))
    assert out.mode == "RGBA"
    assert out.getpixel((0, 0)) == (200, 100, 50, 128)
    assert _iccp_profile(stored) is None


def test_remed2_rgb_color_key_transparency_preserved():
    """Codex P2 round 2 (4503449379): an RGB PNG whose transparency is a
    tRNS color key stores the transparent color in im.info, not the
    pixels — the metadata-free rebuild must convert it to alpha first,
    or formerly transparent pixels come back opaque."""
    img = Image.new("RGB", (8, 8), (255, 0, 0))
    img.putpixel((0, 0), (0, 255, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG", transparency=(255, 0, 0))
    stored, media, w, h = B.validate_and_canonicalize_logo(buf.getvalue())
    out = Image.open(io.BytesIO(stored)).convert("RGBA")
    assert out.getpixel((1, 1)) == (255, 0, 0, 0)  # keyed color: clear
    assert out.getpixel((0, 0)) == (0, 255, 0, 255)  # other pixel: solid


def test_remed2_grayscale_color_key_transparency_preserved():
    """Codex P2 round 2 (4503449379): same tRNS contract for grayscale
    (mode L) PNG logos — the keyed gray level must become alpha 0 and a
    non-keyed level must stay opaque."""
    img = Image.new("L", (8, 8), 128)
    img.putpixel((0, 0), 64)
    buf = io.BytesIO()
    img.save(buf, format="PNG", transparency=128)
    stored, media, w, h = B.validate_and_canonicalize_logo(buf.getvalue())
    out = Image.open(io.BytesIO(stored)).convert("RGBA")
    assert out.getpixel((1, 1))[3] == 0  # keyed gray: clear
    assert out.getpixel((0, 0)) == (64, 64, 64, 255)  # other level: solid


def _form_value(page_text, field):
    m = re.search(r'name="%s"[^>]*value="([^"]*)"' % field, page_text)
    assert m, f"input {field} not found"
    return m.group(1)


def test_remed_partial_save_form_values_empty_not_none(auth_env):
    """Codex P2 (4503408267): after saving only a business name, the
    re-rendered form must show empty values, never the string None."""
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    r = _post_branding(auth_env, dd_id, csrf,
                       data={"business_name": "Acme"})
    assert r.status_code == 200, r.text[:300]
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert page.status_code == 200
    assert 'value="None"' not in page.text
    assert _form_value(page.text, "client_name") == ""
    assert _form_value(page.text, "report_title") == ""
    assert _form_value(page.text, "accent") == ""


def test_remed_cleared_branding_form_values_empty_not_none(auth_env):
    """Codex P2 (4503408267): the retained cleared row (all NULLs) must
    also render empty form values."""
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf, data={
        "business_name": "Acme", "client_name": "Client",
        "report_title": "Title", "accent": "#1a2b3c"}, logo=_png())
    r = auth_env.client.post(f"/reports/{dd_id}/branding/clear",
                             data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert 'value="None"' not in page.text
    assert _form_value(page.text, "business_name") == ""
    assert _form_value(page.text, "accent") == ""


def test_remed_logo_read_410_for_owned_soft_deleted(auth_env):
    """Codex P2 (4503408270): owned soft-deleted (not expired) logo
    read -> 410, matching the A8 lifecycle contract on set/clear."""
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    _expire(auth_env, dd_id, deleted=True)  # deleted AND expired
    r = auth_env.client.get(f"/reports/{dd_id}/branding/logo")
    assert r.status_code == 410


def test_remed_logo_read_410_after_cleanup_soft_delete(auth_env):
    """Codex P2 (4503408270): after cleanup_results() soft-deletes an
    expired report, the owner's logo read is 410, not 404."""
    from app import credit_maintenance
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    _post_branding(auth_env, dd_id, csrf,
                   data={"business_name": "Acme"}, logo=_png())
    _expire(auth_env, dd_id)
    db = auth_env.sessions()
    try:
        credit_maintenance.cleanup_results(db)
    finally:
        db.close()
    r = auth_env.client.get(f"/reports/{dd_id}/branding/logo")
    assert r.status_code == 410


def test_remed_branding_forms_use_inpage_auth_form_pattern(auth_env):
    """Codex P2 (4503408273): both branding forms must be wired to the
    site's in-page auth-form handler with a success URL back to this
    report and a status element, so browser submissions never land on
    a raw JSON page."""
    _email, _uid, _rid, dd_id, csrf = _make_deep_dive(auth_env)
    page = auth_env.client.get(f"/reports/{dd_id}")
    assert page.status_code == 200
    panel = page.text.split("branding-panel")[1].split("</section>")[0]
    set_form = re.search(
        r'<form[^>]*action="/reports/%s/branding"[^>]*>' % dd_id, panel)
    clear_form = re.search(
        r'<form[^>]*action="/reports/%s/branding/clear"[^>]*>' % dd_id,
        panel)
    assert set_form and "data-auth-form" in set_form.group(0)
    assert clear_form and "data-auth-form" in clear_form.group(0)
    assert f'data-success-url="/reports/{dd_id}"' in set_form.group(0)
    assert f'data-success-url="/reports/{dd_id}"' in clear_form.group(0)
    assert 'role="status"' in panel
