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
    # PR #121 head-2 review corpus (findings 1\u20132):
    "2024-01-01 10:00:00 INFO something password\n" * 3,   # label-ending lines
    "password=password\nnext line\n",          # label word as a sealed value
    "password password\nnext line\n",          # label word as a sealed value
    "password=Bearer\nnext line\n",            # Bearer word as a sealed value
    'password=\n"hunter2"\nnext line\n',       # quoted value on the next line
    'password="\nhunter2"\nnext line\n',       # quote before the break: no match
    "pre -----BEGIN PRIVATE KEY----- BODY -----END PRIVATE KEY----- post\n",
    ('password="-----BEGIN PRIVATE KEY-----\nBODY\n'
     '-----END PRIVATE KEY-----hunter2"\nnext line\n'),    # finding 2
    # PR #121 head-3 review corpus:
    "password=Bearer\nabcdefghijklmnopqrstuvwx\nnext line\n",  # Bearer claims next line
    "password=\n   \n\t\n  \nhunter2\nnext line\n",            # whitespace-run tail
    "password=\nBearer\nnext line\n",              # Bearer word as the label's value
    "password=\nBearer\nabcdefghijklmnopqrstuvwx\n",  # ... then Bearer claims a token
    # PR #121 head-4 review corpus:
    "Bearer abcdefghijpassword=Bearer\nabcdefghijklmnopqrstuvwx\n",  # cut inside a token
    "ghp_" + "a" * 20 + "password=password=\nhunter2\nnext line\n",  # phantom label in a token
    "-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----- " * 3 + "tail\n",
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


# --- Codex review findings on PR #121 head 2 (all verified) -----------------
#
# Head 2 fixed the per-line redaction divergences but introduced a
# state machine that (1) deferred the WHOLE pending buffer whenever
# its tail looked extendable, (2) emitted a PEM block's prefix and
# replacement separately, breaking a labeled credential whose value
# contained the block, and (3) wrote adapted JSON-lines with a
# trailing newline per line instead of join semantics.


def test_pem_block_inside_labeled_credential_value_redacted():
    # Finding 2: whole-text redaction runs the PEM pattern BEFORE the
    # labeled-credential pattern, so password="<PEM block>hunter2"
    # collapses to password=[REDACTED]. Emitting the prefix, the PEM
    # replacement, and the suffix as separate segments leaked hunter2.
    content = (
        '2024-01-01 10:00:00 ERROR password="-----BEGIN PRIVATE KEY-----\n'
        "BODY\n"
        '-----END PRIVATE KEY-----hunter2"\n'
        "2024-01-01 10:01:00 INFO ok\n"
    ).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    blob = json.dumps(out, default=str)
    assert "hunter2" not in blob
    assert "BODY" not in blob
    legacy = analyze_upload("s.log", content)
    assert "error" not in legacy, legacy
    assert out["results"]["level_counts"] == legacy["results"]["level_counts"]
    assert out["results"]["total_lines"] == legacy["results"]["total_lines"]


def test_jsonlines_trailing_blank_line_matches_legacy_counts():
    # Finding 3 (P3): the legacy adaptation is "\n".join(lines); a
    # record followed by a blank line is ONE line to the analyzer.
    # Appending "\n" after every adapted line made it two lines, the
    # second counted malformed.
    record = {"timestamp": "2024-01-01T10:00:00Z", "level": "error",
              "message": "disk full"}
    content = (json.dumps(record) + "\n\n").encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    assert out["detected_format"] == "jsonlines"
    assert out["results"]["total_lines"] == 1
    assert out["results"]["malformed_lines"] == 0
    legacy = analyze_upload("s.log", content)
    assert "error" not in legacy, legacy
    assert out["results"]["total_lines"] == legacy["results"]["total_lines"]
    assert out["results"]["malformed_lines"] == legacy["results"]["malformed_lines"]


def test_label_ending_lines_do_not_accumulate_pending(monkeypatch):
    # Finding 1 (P2): lines ending in a bare label word make the tail
    # "extendable" on every line. Head 2 deferred the entire pending
    # buffer each time, so the decoded upload accumulated (and was
    # rescanned) whole \u2014 a 92 MB fixture of such lines timed out the
    # supervised worker at 60s. Head 3 emits the finalized prefix and
    # holds only the unresolved suffix: peak preprocessing memory
    # stays in the one-line class, and the output still equals
    # whole-text redaction exactly.
    import hashlib
    import tracemalloc

    from app.redact import redact_secrets

    monkeypatch.setattr(service, "_DECODE_CHUNK_BYTES", 65536)
    line = "2024-01-01 10:00:00 INFO " + "x" * 50000 + " password\n"
    text = line * 80  # ~4 MB of label-ending lines
    content = text.encode()
    expected = hashlib.sha256(redact_secrets(text).encode()).hexdigest()
    digest = hashlib.sha256()
    tracemalloc.start()
    try:
        # Consume segment by segment: the test itself must not
        # accumulate the output it is measuring.
        for segment in service._redacted_chunks(content):
            digest.update(segment.encode())
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert digest.hexdigest() == expected
    assert peak < 2_000_000, peak


# --- Codex review findings on PR #121 head 3 (all verified) -----------------
#
# Head 3's flush split introduced two new divergences: its
# sealed-match adjustment ignored pattern ORDER (a later pattern's
# match cannot seal an earlier pattern's unresolved candidate), and a
# held suffix made only of whitespace was still rescanned per line.


def test_bearer_value_of_label_still_claims_next_line():
    # Finding (4437859484): redact_secrets() applies the Bearer
    # pattern BEFORE the labeled pattern, so in
    # "password=Bearer\n<token>" the Bearer match consumes the token
    # first and the labeled match then redacts "Bearer" itself.
    # Head 3 let the labeled match seal the Bearer candidate and
    # flushed the first line, leaking the token verbatim.
    content = (
        "2024-01-01 10:00:00 ERROR password=Bearer\n"
        "abcdefghijklmnopqrstuvwx\n"
        "2024-01-01 10:01:00 INFO ok\n"
    ).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    blob = json.dumps(out, default=str)
    assert "abcdefghijklmnopqrstuvwx" not in blob
    legacy = analyze_upload("s.log", content)
    assert "error" not in legacy, legacy
    assert out["results"]["level_counts"] == legacy["results"]["level_counts"]
    assert out["results"]["total_lines"] == legacy["results"]["total_lines"]


def test_whitespace_tail_after_label_is_not_rescanned():
    # Finding (4437859489): the exact Codex fixture \u2014 a label, then
    # 12,000 whitespace-only lines, then the value (12,012,018 bytes).
    # Head 3 rescanned the growing held buffer on every line and the
    # supervised worker timed out; the pre-#116 whole-text flow needs
    # ~0.14s. Head 4 tracks the whitespace tail by state: the stream
    # completes in the whole-text class and equals it exactly.
    import time

    from app.redact import redact_secrets

    content = b"password=\n" + (b" " * 1000 + b"\n") * 12000 + b"hunter2\n"
    assert len(content) == 12_012_018
    start = time.perf_counter()
    streamed = "".join(service._redacted_chunks(content))
    elapsed = time.perf_counter() - start
    assert streamed == redact_secrets(content.decode())
    assert "hunter2" not in streamed
    assert elapsed < 10, elapsed


# --- Codex review findings on PR #121 head 4 (all verified) -----------------
#
# Head 4's order-aware sealing still decided cuts from raw-text
# matches: a cut at a labeled match's start could split an earlier
# Bearer token, and a labeled match starting inside a ghp_ token
# (consumed by the earlier token substitution) phantom-sealed a real
# candidate. Head 5 decides from pattern-order CLAIMED intervals and
# guards every cut against claimed matches. Separately, complete PEM
# blocks on one line were substituted one rebuild-and-rescan at a
# time (quadratic); head 5 substitutes in a single cursor pass.


def test_cut_must_not_split_earlier_bearer_token():
    # Finding (4437955155): the labeled match "password=Bearer" starts
    # INSIDE a Bearer token; cutting at its start left a 10-char token
    # fragment in the emitted prefix, below the Bearer pattern's
    # threshold, leaking it into the report.
    content = (
        "2024-01-01 10:00:00 ERROR Bearer abcdefghijpassword=Bearer\n"
        "abcdefghijklmnopqrstuvwx\n"
        "2024-01-01 10:01:00 INFO ok\n"
    ).encode()
    out = analyze_upload("s.log", content, allow_oversize=True, use_alarm=False)
    assert "error" not in out, out
    blob = json.dumps(out, default=str)
    assert "abcdefghijpassword" not in blob
    assert "abcdefghijklmnopqrstuvwx" not in blob
    legacy = analyze_upload("s.log", content)
    assert "error" not in legacy, legacy
    assert out["results"]["level_counts"] == legacy["results"]["level_counts"]
    assert out["results"]["total_lines"] == legacy["results"]["total_lines"]


def test_many_pem_blocks_on_one_line_single_pass():
    # Finding (4437955165): one physical line holding many complete
    # PEM blocks must be substituted in one pass, not rebuilt and
    # rescanned per block (quadratic). This is Codex's exact fixture:
    # 100k blocks, 5.7 MB, one line \u2014 head 4 timed the supervised
    # worker out at 60s on it; the whole-text flow needs ~0.34s.
    import time

    from app.redact import redact_secrets

    text = "-----BEGIN PRIVATE KEY-----body-----END PRIVATE KEY----- " * 100000
    start = time.perf_counter()
    streamed = "".join(service._redacted_chunks(text.encode()))
    elapsed = time.perf_counter() - start
    assert streamed == redact_secrets(text)
    assert "body" not in streamed
    assert elapsed < 10, elapsed


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


# --- Codex review findings on PR #121 head 5 (all verified) -----------------
#
# Head 5's _claimed_matches discarded phantoms via finditer, whose
# advancement past a phantom also swallows a real match that overlaps
# the phantom's span; and its inside-a-claim test scanned every
# previous claim, quadratic on a line holding many tokens. Head 6
# resumes the scan at phantom.start() + 1 and indexes claims as
# merged intervals (bisect).


def test_phantom_discard_does_not_swallow_overlapping_real_match():
    # Finding (4438198364): the labeled match starting inside this
    # Bearer token is a phantom (the token pattern claimed the
    # region), but its secret run extends past the token and covers
    # a REAL second label. Discarding the phantom must still
    # discover the real match as a claim.
    from app.redact import redact_secrets

    text = "ERROR Bearer aaaaaaaaapassword=va!uepassword=hunter2 done\n"
    claims = service._claimed_matches(text)
    labeled = [c for c in claims if c[2] == service._LABELED_ORDER]
    assert labeled, claims
    start, end, _order = labeled[0]
    assert text[start:end].startswith("password=hunter2")
    streamed = "".join(service._redacted_chunks(text.encode()))
    assert streamed == redact_secrets(text)
    assert "hunter2" not in streamed


def test_many_tokens_line_claims_not_quadratic():
    # Finding (4438198370): Codex's exact fixture \u2014 100k ghp_
    # tokens on one line ending in an extendable label. Head 5's
    # per-match claim scan times the supervised worker out at 60s;
    # the whole-text flow needs ~0.3s.
    import time

    from app.redact import redact_secrets

    text = ("ghp_" + "a" * 20 + " ") * 100000 + "password=\nhunter2\n"
    start = time.perf_counter()
    streamed = "".join(service._redacted_chunks(text.encode()))
    elapsed = time.perf_counter() - start
    assert streamed == redact_secrets(text)
    assert "hunter2" not in streamed
    assert elapsed < 10, elapsed
