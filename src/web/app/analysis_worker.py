"""Supervised worker for oversize analysis (issue #104).

SHARED INFRASTRUCTURE (approval trim T7): this module is the supervised-
worker foundation for oversize analysis now and for batch (#103) and
compare (#102) later. Later features REUSE it; they do not build a second
worker.

Design (approval trims T1, T5):
- Oversize preprocessing/analysis runs in a supervised subprocess and
  never moves SIGALRM into a thread. The /analyze/paid route runs the
  oversize path in a worker thread (main.py analyze_paid), so the
  up-to-60s subprocess wait never blocks the async event loop. The
  standard path keeps its 25-second SIGALRM; the subprocess runs with
  use_alarm=False and the PARENT enforces the deadline via
  subprocess timeout (stop + join before any ledger release, since
  settlement only happens after run_supervised() returns).
- The 60-second deadline and 512 MiB address-space ceiling are named,
  configurable BENCHMARK CANDIDATES (T1), not promises: final values are
  set from staging measurements, and no UI copy promises a time or memory
  figure. The single-replica assumption (T3) applies: pending files and
  the in-process worker pool live on one instance; a multi-replica
  finding blocks production promotion, not the staging merge.

The child is invoked as ``python -m app.analysis_worker <in> <out>`` with
PYTHONPATH pointed at this package's parent directory, so it works
regardless of the parent process's working directory. The child writes
the analyze_upload() result dict as JSON (default=str, matching the
ledger's storage convention); the parent returns it with the original
filename restored (the child only ever sees ``input.log``), including
error dicts, so settlement treats worker failures exactly like
in-process failures (full reservation reversal, no result published).

The child's own temporary file (service.py's NamedTemporaryFile) is
contained by pointing the child's TMPDIR at the parent-owned per-run
directory, which the parent removes wholesale (shutil.rmtree) after the
child is stopped and joined — so a timeout kill, which bypasses the
child's own finally-unlink, cannot orphan a redacted temp file in the
system temp directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Benchmark candidates (T1) — tune only from staging measurements.
OVERSIZE_EXECUTION_TIMEOUT_SECONDS = 60
OVERSIZE_MEMORY_LIMIT_BYTES = 512 * 1024 * 1024


def _package_parent() -> str:
    """Directory containing the ``app`` package (for the child's PYTHONPATH)."""
    return str(Path(__file__).resolve().parent.parent)


def run_supervised(filename: str, content: bytes, *,
                   timeout: int = OVERSIZE_EXECUTION_TIMEOUT_SECONDS,
                   memory_limit: int = OVERSIZE_MEMORY_LIMIT_BYTES,
                   original_byte_count: int | None = None,
                   collect_comparison_evidence: bool = False) -> dict:
    """Run an oversize analysis in a supervised subprocess.

    Returns the analyze_upload() result dict on success, or an error dict
    (with "error" and "message" keys, like analyze_upload failures) when
    the worker times out, crashes, or produces no output. The subprocess
    is always stopped and joined (subprocess.run kills on timeout and
    waits) before this function returns, so the caller may safely settle
    the ledger reservation afterwards.

    original_byte_count (PR #111 finding 6): the server-measured original
    byte count for a confirmed oversize run. It is passed to the child
    (STACKSIFT_OVERSIZE_ORIGINAL_BYTES) so the child's byte-ceiling check
    runs against the originals, not the redacted bytes it receives — see
    service.analyze_upload. None preserves the previous len(content)
    behavior for direct (non-confirmation) worker calls.
    """
    tmp_dir = tempfile.mkdtemp(prefix="stacksift-oversize-")
    in_path = os.path.join(tmp_dir, "input.log")
    out_path = os.path.join(tmp_dir, "output.json")
    try:
        with open(in_path, "wb") as f:
            f.write(content)
        env = dict(os.environ)
        env["PYTHONPATH"] = _package_parent() + os.pathsep + env.get("PYTHONPATH", "")
        env["STACKSIFT_OVERSIZE_MEMORY_LIMIT"] = str(memory_limit)
        if original_byte_count is not None:
            env["STACKSIFT_OVERSIZE_ORIGINAL_BYTES"] = str(original_byte_count)
        # Issue #102: compare reuses this worker (spec trim C1); the child
        # threads the flag into analyze_upload so the evidence collector
        # runs only for comparison inputs, never for oversize runs.
        if collect_comparison_evidence:
            env["STACKSIFT_COLLECT_COMPARISON_EVIDENCE"] = "1"
        # Contain the child's service temp file inside this per-run
        # directory (see module docstring): the parent removes the whole
        # directory after the child stops, even on a timeout kill.
        env["TMPDIR"] = tmp_dir
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "app.analysis_worker", in_path, out_path],
                timeout=timeout, capture_output=True, env=env,
            )
        except subprocess.TimeoutExpired:
            # subprocess.run kills the child and waits for it (stop + join).
            return {
                "error": "analysis_timeout",
                "message": f"Oversize analysis exceeded {timeout}s timeout. "
                           "The log may contain pathological patterns.",
                "filename": filename,
            }
        if proc.returncode != 0 or not os.path.exists(out_path):
            return {
                "error": "worker_failed",
                "message": "Oversize analysis worker failed before producing a result.",
                "filename": filename,
            }
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {
                "error": "worker_failed",
                "message": "Oversize analysis worker returned an invalid result.",
                "filename": filename,
            }
        # Overwrite, not setdefault: the child only ever saw "input.log",
        # so its result dict already carries that name and setdefault
        # would never restore the user's original filename.
        data["filename"] = filename
        return data
    finally:
        # Remove the whole per-run directory, including any temp file the
        # child left behind when it was killed on timeout. rmtree runs
        # only after subprocess.run has stopped and joined the child.
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _child_main(argv: list[str]) -> int:
    """Child entry point: analyze one file, write the result JSON."""
    if len(argv) != 2:
        print("usage: python -m app.analysis_worker <input> <output>", file=sys.stderr)
        return 2
    in_path, out_path = argv
    # Address-space ceiling (benchmark candidate, T1). Best effort: if the
    # platform lacks resource limits, the parent timeout still bounds us.
    try:
        import resource
        limit = int(os.environ.get("STACKSIFT_OVERSIZE_MEMORY_LIMIT", "0") or 0)
        if limit > 0:
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ImportError, ValueError, OSError):
        pass
    from app.service import analyze_upload
    with open(in_path, "rb") as f:
        content = f.read()
    # use_alarm=False (T5): the parent enforces the deadline; SIGALRM is
    # never armed in a thread and never double-arms this process.
    # PR #111 finding 6: pass the server-measured original byte count
    # through (when the parent supplied one) so the byte ceiling is not
    # re-applied to the redacted bytes the child receives.
    original_byte_count = None
    try:
        original_byte_count = int(os.environ.get("STACKSIFT_OVERSIZE_ORIGINAL_BYTES", "") or 0) or None
    except ValueError:
        original_byte_count = None
    data = analyze_upload(os.path.basename(in_path), content,
                          allow_oversize=True, use_alarm=False,
                          original_byte_count=original_byte_count,
                          collect_comparison_evidence=(
                              os.environ.get("STACKSIFT_COLLECT_COMPARISON_EVIDENCE") == "1"))
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(_child_main(sys.argv[1:]))
