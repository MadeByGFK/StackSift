"""Issue #103: batch analysis — real execution and resource guardrails.

The HTTP/ledger suite mocks main._execute_batch; here the REAL path
runs: sequential execution in upload order through the shared #104
supervised worker (trim B3), the 150s outer deadline orchestration,
and the B4 budget derivation constants. Fixtures are generated
programmatically — no large files are committed.
"""

import pytest

from app import main
from app.analysis_worker import run_supervised
from app.batch_service import MAX_BATCH_FILES
from app.service import MAX_UPLOAD_BYTES, MAX_UPLOAD_LINES, count_original_lines


def _log(level, message, n):
    return (f"2024-01-01 10:00:00 {level} {message}\n".encode() * n)


def test_execute_batch_real_worker_sequential_order():
    files = [
        (1, "first.log", _log("ERROR", "first file failure", 7)),
        (2, "second.log", _log("WARN", "second file warning", 3)),
        (3, "third.log", _log("INFO", "heartbeat ok", 2)),
    ]
    results = main._execute_batch(files)
    assert len(results) == 3
    for (ordinal, filename, _content), result in zip(files, results):
        assert "error" not in result, result
        assert result["filename"] == filename
    assert results[0]["results"]["level_counts"]["ERROR"] == 7
    assert results[1]["results"]["level_counts"]["WARN"] == 3
    # The worker restored the original filenames (never "input.log").
    assert all(r["filename"] != "input.log" for r in results)


def test_execute_batch_outer_deadline(monkeypatch):
    monkeypatch.setattr(main, "BATCH_OUTER_DEADLINE_SECONDS", 0)
    results = main._execute_batch([(1, "a.log", _log("INFO", "x", 1)),
                                   (2, "b.log", _log("INFO", "y", 1))])
    assert len(results) == 1
    assert results[0]["error"] == "analysis_timeout"


def test_execute_batch_worker_failure_is_error_dict():
    # A worker-level failure (memory ceiling tripped) surfaces as an
    # error dict for that file, which settlement turns into a full
    # release — never a partial batch result.
    from app import analysis_worker

    def failing(filename, content, **kwargs):
        return {"error": "worker_failed", "message": "worker died",
                "filename": filename}

    import app.main as m
    orig = analysis_worker.run_supervised
    analysis_worker.run_supervised = failing
    try:
        results = m._execute_batch([(1, "a.log", b"x\n")])
    finally:
        analysis_worker.run_supervised = orig
    assert results[0]["error"] == "worker_failed"
    assert run_supervised is orig


def test_b4_budget_derivation_constants():
    """Trim B4 re-derivation (see batch_service module docstring):
    post-#104 the pending budget is 256 MiB; the worst-case batch is
    5 files x the 10 MiB FREE ceiling = 50 MiB, and the pre-multipart
    guard is that plus 1 MiB of form overhead."""
    assert MAX_BATCH_FILES == 5
    worst_case = MAX_BATCH_FILES * MAX_UPLOAD_BYTES
    assert worst_case == 50 * 1024 * 1024
    assert worst_case < main._PAID_PENDING_BUDGET  # 256 MiB aggregate ceiling
    assert main._PAID_PENDING_BUDGET == 256 * 1024 * 1024
    assert main._BATCH_GUARD_BYTES == worst_case + 1024 * 1024
    assert main.BATCH_OUTER_DEADLINE_SECONDS == 150


def test_generated_max_batch_validates_at_free_limits():
    """Programmatically generated maximum-size bundle: 5 files, each
    exactly at the free line ceiling, all within the guard bytes."""
    line = b"2024-01-01 10:00:00 INFO heartbeat ok\n"
    content = line * MAX_UPLOAD_LINES
    assert len(content) < MAX_UPLOAD_BYTES
    total = 0
    for _ in range(MAX_BATCH_FILES):
        assert count_original_lines(content) == MAX_UPLOAD_LINES
        total += len(content)
    assert total < main._BATCH_GUARD_BYTES
