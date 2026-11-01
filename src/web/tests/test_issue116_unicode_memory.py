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


# --- Codex review findings on PR #121 (all verified, all remediated) --------
#
# The first streaming draft redacted strictly per splitlines() line,
# which diverged from whole-text redact_secrets() in four ways. The
# shipped implementation streams PHYSICAL lines through a redaction
# state machine (_redacted_chunks) instead; these tests pin each
# finding's case.

EQUIVALENCE_TEXTS = [
    "plain log line\nanother line\n",
    "2024-01-01 10:00:00 INFO password=hunter2 login\n",
    "Bearer abcdefghijklmnopqrstuvwx\nnext line\n",
    "Bearer\nabcdefghijklmnopqrstuvwx\nnext line\n",          # cross-line Bearer
    "password=\nhunter2\nnext line\n",                        # cross-line labeled
    "password=\n\n\nhunter2\n",                               # labeled, blank lines between
    "the password\nis not a credential\n",                    # prose label, no separator
    "-----BEGIN PRIVATE KEY-----\nMIIabc\nMIIdef\n-----END PRIVATE KEY-----\n",
    "pre -----BEGIN PRIVATE KEY-----\nBODY1\n-----END PRIVATE KEY----- post\n",
    ("-----BEGIN PRIVATE KEY-----\nAAA\n"
     "-----END PRIVATE KEY----- -----BEGIN PRIVATE KEY-----\n"
     "SECONDBODY\n-----END PRIVATE KEY-----\ntail\n"),        # finding 1: BEGIN on END line
    "api_key = 'zzz123456789'\n",
    "token is ghp_abcdefghijklmnopqrstuvwx1234567890 ok\n",
    "a\rb\r\nc\nd",
    "unicode \U0001F600 and\u2028separators\x85here\n",
]


def test_redacted_chunks_match_whole_text_redaction():
    from app.redact import redact_secrets
    for text in EQUIVALENCE_TEXTS:
        streamed = "".join(service._redacted_chunks(text.encode("utf-8")))
        assert streamed == redact_secrets(text), text


def test_pem_end_line_suffix_is_reprocessed_not_dropped():
    # Finding 1, content side: text after an END marker on the same line
    # is reprocessed as fresh input, exactly as whole-text redaction
    # leaves it (appended to the [REDACTED] line the block collapses
    # to) — and the streaming result equals the legacy standard path's.
    content = (
        "-----BEGIN PRIVATE KEY-----\nAAA\n"
        "-----END PRIVATE KEY----- 2024-01-01 10:00:00 ERROR after the block\n"
    ).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    assert "AAA" not in json.dumps(out["results"], default=str)
    legacy = analyze_upload("s.log", content)
    assert "error" not in legacy, legacy
    assert out["results"]["level_counts"] == legacy["results"]["level_counts"]
    assert out["results"]["total_lines"] == legacy["results"]["total_lines"]
    assert out["results"]["parsed_lines"] == legacy["results"]["parsed_lines"]


def test_second_pem_begin_on_end_line_does_not_leak():
    # Finding 1, leak side: a second BEGIN marker sharing the first
    # block's END line starts a new block; its body must be dropped,
    # not written. The body here is an ERROR line, so a leak would be
    # retained in the result as an issue — fully observable.
    content = (
        "-----BEGIN PRIVATE KEY-----\nAAA\n"
        "-----END PRIVATE KEY----- -----BEGIN PRIVATE KEY-----\n"
        "2024-01-01 10:00:00 ERROR SECRETMARKER\n"
        "-----END PRIVATE KEY-----\n"
        "2024-01-01 11:00:00 INFO ok\n"
    ).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    blob = json.dumps(out, default=str)
    assert "SECRETMARKER" not in blob
    assert out["results"]["level_counts"].get("ERROR", 0) == 0
    legacy = analyze_upload("s.log", content)
    assert out["results"]["level_counts"] == legacy["results"]["level_counts"]
    assert out["results"]["total_lines"] == legacy["results"]["total_lines"]


def test_cross_line_credentials_do_not_leak():
    # Finding 2: Bearer and labeled credentials split across lines.
    # Whole-text redaction matches across the newline (\\s+ / \\s*),
    # merging the pair into one redacted line; per-line redaction
    # leaked the value as its own line (observable as an extra line
    # and, for the ERROR cases, a retained unredacted issue).
    content = (
        "2024-01-01 10:00:00 ERROR Bearer\n"
        "abcdefghijklmnopqrstuvwx\n"
        "2024-01-01 10:01:00 ERROR password=\n"
        "hunter2\n"
        "2024-01-01 10:02:00 INFO ok\n"
    ).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    blob = json.dumps(out, default=str)
    assert "abcdefghijklmnopqrstuvwx" not in blob
    assert "hunter2" not in blob
    legacy = analyze_upload("s.log", content)
    assert "error" not in legacy, legacy
    assert out["results"]["level_counts"] == legacy["results"]["level_counts"]
    assert out["results"]["total_lines"] == legacy["results"]["total_lines"]


def test_jsonlines_sampling_uses_redacted_stream_window():
    # Finding 3: a >200-line PEM block collapses to one redacted line,
    # so JSON records after it fall inside the 200-line sample window
    # of the redacted stream (legacy behavior) and are adapted.
    pem = ("-----BEGIN PRIVATE KEY-----\n"
           + "BODYLINE\n" * 205
           + "-----END PRIVATE KEY-----\n")
    rows = [
        {"time": "2024-01-01T10:00:00Z", "severity": "error", "msg": "disk full"},
        {"time": "2024-01-01T10:01:00Z", "severity": "error", "msg": "disk full"},
    ]
    content = (pem + "\n".join(json.dumps(r) for r in rows) + "\n").encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    assert out["detected_format"] == "jsonlines"
    assert out["results"]["level_counts"]["ERROR"] == 2


def test_literal_u2028_inside_json_record_preserved():
    # Finding 4: unadapted text is written verbatim; a literal U+2028
    # inside a JSON record must not split the record into two lines.
    record = {"timestamp": "2024-01-01T10:00:00Z", "level": "error",
              "message": "boom\u2028rest"}
    content = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    assert out["results"]["total_lines"] == 1
    assert out["results"]["level_counts"]["ERROR"] == 1
    assert out["results"]["malformed_lines"] == 0


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
