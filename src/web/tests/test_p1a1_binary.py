"""Regression tests for P1-A1: Binary detection via magic bytes.

The 30% non-text threshold missed files with mostly-ASCII binary headers
(e.g., PNG headers are only ~17% non-text). Magic-byte signatures catch
these before content analysis.
"""
import sys
sys.path.insert(0, 'src/web')

from app.service import _is_binary_content, analyze_upload


def test_png_magic_bytes():
    """PNG header (\\x89PNG) detected even though mostly ASCII."""
    # This specific case failed before P1-A1: 16.7% non-text < 30% threshold
    png = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] * 50)
    assert _is_binary_content(png), "PNG not detected as binary"
    r = analyze_upload("test.log", png)
    assert r.get('error') == 'binary_file', "PNG not rejected"
    print("✓ PNG magic bytes detected")


def test_pdf_magic_bytes():
    pdf = b"%PDF-1.4 fake content\n" * 50
    assert _is_binary_content(pdf), "PDF not detected"
    print("✓ PDF magic bytes detected")


def test_pdf_export_text_not_rejected():
    """Text starting with '%PDF-' but no version must not be rejected.
    
    ChatGPT re-review: '%PDF-export completed successfully' was rejected.
    Real PDFs have %PDF- followed by a digit (e.g., %PDF-1.4).
    """
    text = b"%PDF-export completed successfully\n" * 10
    assert not _is_binary_content(text), "%PDF-export text false positive!"
    r = analyze_upload("test.log", text)
    assert r.get('error') != 'binary_file', "%PDF-export text rejected!"
    print("✓ %PDF-export text not rejected")


def test_pdf_without_version_not_rejected():
    """Bare '%PDF' without version suffix is not a PDF."""
    text = b"%PDF content\n" * 10
    assert not _is_binary_content(text), "Bare %PDF false positive!"
    print("✓ Bare %PDF not rejected")


def test_zip_magic_bytes():
    """ZIP header also covers JAR, DOCX, XLSX."""
    zip_data = b"PK\x03\x04" + b"fake" * 50
    assert _is_binary_content(zip_data), "ZIP not detected"
    print("✓ ZIP magic bytes detected")


def test_jpeg_magic_bytes():
    jpeg = b"\xff\xd8\xff" + b"fake" * 50
    assert _is_binary_content(jpeg), "JPEG not detected"
    print("✓ JPEG magic bytes detected")


def test_gzip_magic_bytes():
    gzip_data = b"\x1f\x8b" + b"fake" * 50
    assert _is_binary_content(gzip_data), "GZIP not detected"
    print("✓ GZIP magic bytes detected")


def test_valid_log_not_rejected():
    """Valid text logs must not be flagged as binary."""
    log = b"2026-10-12 12:00:00 INFO test message\n" * 100
    assert not _is_binary_content(log), "Valid log flagged as binary!"
    r = analyze_upload("test.log", log)
    assert r.get('error') != 'binary_file', "Valid log rejected!"
    print("✓ Valid logs not rejected")


def test_empty_not_binary():
    assert not _is_binary_content(b""), "Empty flagged as binary"
    print("✓ Empty content not flagged")


def test_nul_byte_still_detected():
    """Original NUL-byte detection still works."""
    data = b"some text\x00more text" * 100
    assert _is_binary_content(data), "NUL byte not detected"
    print("✓ NUL byte detection preserved")


def test_high_control_char_ratio_still_detected():
    """Original 30% threshold still works for non-magic binaries.
    
    ChatGPT review: bytes(range(256)) contains NUL, so it triggers NUL
    detection without exercising the ratio check. Use NUL-free fixture.
    """
    # 40% control chars (\\x01), 60% text — no NUL bytes
    data = b"\x01" * 40 + b"A" * 60
    assert _is_binary_content(data), "High control-char ratio not detected"
    print("✓ Control-char ratio detection preserved")


def test_mz_text_not_rejected():
    """Text starting with 'MZ' must not be rejected (ChatGPT review)."""
    text = b"MZ service started successfully\n" * 10
    assert not _is_binary_content(text), "MZ text false positive!"
    r = analyze_upload("test.log", text)
    assert r.get('error') != 'binary_file', "MZ text rejected!"
    print("✓ MZ text not rejected")


def test_real_mz_executable_detected():
    """Real MZ executables (with NUL bytes) are still detected."""
    mz = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50
    assert _is_binary_content(mz), "Real MZ not detected"
    print("✓ Real MZ executable detected")


if __name__ == "__main__":
    test_png_magic_bytes()
    test_pdf_magic_bytes()
    test_pdf_export_text_not_rejected()
    test_pdf_without_version_not_rejected()
    test_zip_magic_bytes()
    test_jpeg_magic_bytes()
    test_gzip_magic_bytes()
    test_valid_log_not_rejected()
    test_empty_not_binary()
    test_nul_byte_still_detected()
    test_high_control_char_ratio_still_detected()
    test_mz_text_not_rejected()
    test_real_mz_executable_detected()
    print("\n✅ All P1-A1 regression tests passed!")
