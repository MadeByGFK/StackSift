"""Issue #116: oversize worker decoded-Unicode memory bound.

Fast-follow for the Codex P2 on PR #115: a valid UTF-8 oversize upload
whose lines carry non-BMP characters (emoji) classified as supported,
but run_supervised() returned worker_failed because the child decoded
the whole upload into one str — at 4 bytes per character for the whole
string once any non-BMP character is present — and died with MemoryError
under the 512 MiB ceiling before analysis started.

The fix streams the oversize preprocessing in app.service
(_iter_decoded_lines / _oversize_preflight /
_write_streamed_analysis_file): peak preprocessing memory is bounded by
the longest line, not the decoded size of the upload. The standard
(free) path is untouched.

The ~90 MB regression test below is the acceptance fixture from the
issue (100 lines x ~900 KiB ASCII + one emoji each, 92,160,500 bytes):
it FAILS on the pre-fix tree (worker_failed / MemoryError at decode)
and passes on the built tree (teeth check, verified 2026-11-01).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app import service
from app.analysis_worker import run_supervised
from app.service import analyze_upload


# --- line iteration equivalence --------------------------------------------

TRICKY_TEXTS = [
    "",
    "one line no break",
    "a\nb\n",
    "a\nb",
    "a\r\nb\r\n",
    "a\rb\n",
    "a\n\n\nb",
    "\n",
    "\r\n",
    "a\x85b\u2028c\u2029d",          # Unicode line breaks
    "a\x0bb\x0cc\x1cd\x1de\x1ef",    # ASCII splitlines breaks
    "emoji \U0001F600 line\nsecond \U0001F600\n",
    "trailing break\r",
    "mixed\r\n\n\rend",
]


def test_iter_decoded_lines_matches_splitlines(monkeypatch):
    # Tiny decode chunks force multi-byte characters and CRLF pairs to
    # straddle chunk boundaries — equivalence with splitlines() must
    # hold anyway.
    monkeypatch.setattr(service, "_DECODE_CHUNK_BYTES", 3)
    for text in TRICKY_TEXTS:
        content = text.encode("utf-8")
        assert list(service._iter_decoded_lines(content)) == text.splitlines(), text


def test_iter_decoded_lines_invalid_utf8_replaced(monkeypatch):
    monkeypatch.setattr(service, "_DECODE_CHUNK_BYTES", 2)
    content = b"ok \xff\xfe line\nnext\n"
    expected = content.decode("utf-8", errors="replace").splitlines()
    assert list(service._iter_decoded_lines(content)) == expected


# --- streaming oversize semantics (small fixtures) --------------------------

def test_oversize_streaming_jsonlines_detected_and_adapted():
    rows = [
        {"timestamp": "2024-01-01T10:00:00Z", "level": "error",
         "message": "disk full"},
        {"timestamp": "2024-01-01T10:01:00Z", "level": "info",
         "message": "heartbeat ok"},
    ]
    content = ("\n".join(json.dumps(r) for r in rows) + "\n").encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    assert out["detected_format"] == "jsonlines"
    assert out["adapted"] is True
    assert out["results"]["level_counts"]["ERROR"] == 1
    assert out["results"]["level_counts"]["INFO"] == 1


def test_oversize_streaming_redacts_secrets_and_multiline_pem():
    secret_body = "MIISECRETKEYMATERIAL"
    content = (
        "2024-01-01 10:00:00 INFO password=hunter2 login\n"
        "-----BEGIN PRIVATE KEY-----\n"
        f"{secret_body}\n"
        "-----END PRIVATE KEY-----\n"
        "2024-01-01 10:02:00 ERROR disk full\n"
    ).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    blob = json.dumps(out, default=str)
    assert "hunter2" not in blob
    assert secret_body not in blob
    assert out["results"]["level_counts"]["ERROR"] == 1


def test_oversize_streaming_unicode_small_still_analyzes():
    content = ("2024-01-01 10:00:00 INFO launch \U0001F600 ok\n" * 5).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    assert out["results"]["level_counts"]["INFO"] == 5


# --- the acceptance fixture: ~90 MB class, non-BMP heavy --------------------

def test_nonbmp_heavy_90mb_class_passes_supervised_worker():
    # The exact shape Codex reproduced on PR #115: 100 INFO lines, each
    # ~900 KiB of ASCII plus one non-BMP emoji (92,160,500 bytes total).
    emoji = "\U0001F600".encode("utf-8")
    line = b"2024-01-01 10:00:00 INFO " + b"x" * (900 * 1024 - 25) + emoji + b"\n"
    content = line * 100
    assert len(content) == 92_160_500
    data = run_supervised("big.log", content)
    assert "error" not in data, data
    assert data["results"]["total_lines"] == 100
    assert data["results"]["level_counts"]["INFO"] == 100
