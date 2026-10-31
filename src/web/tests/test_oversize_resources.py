"""Issue #104: oversize resource benchmark entry point (draft §7/§8).

Running this module directly generates genuine large fixtures
programmatically (no 100 MiB artifacts are committed), executes the
production worker path (app.analysis_worker.run_supervised), and prints
input bytes, line count, wall time, peak RSS, and the configured resource
limits:

    PYTHONPATH=src/web python src/web/tests/test_oversize_resources.py --benchmark

It is NOT run by pytest: the pytest tests below cover only cheap worker
properties (constants, small supervised runs). Staging acceptance (trim
T9, post-merge, before ANY production promotion) repeats the benchmark
there with the genuine 500,000-line and near-100-MiB fixtures and records
elapsed time, peak RSS, success delta -3, and forced-failure delta 0.

Resource figures here are benchmark candidates (trim T1), not promises:
no UI copy promises a time or memory figure.
"""

import argparse
import os
import resource
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.analysis_worker import (
    OVERSIZE_EXECUTION_TIMEOUT_SECONDS,
    OVERSIZE_MEMORY_LIMIT_BYTES,
    run_supervised,
)


def generate_line_fixture(nlines, path):
    """Write nlines of realistic log lines (programmatic, not committed)."""
    line = b"2024-01-01 10:00:00 INFO heartbeat ok\n"
    with open(path, "wb") as f:
        for _ in range(nlines):
            f.write(line)


def generate_byte_fixture(target_bytes, path):
    """Write ~target_bytes of long-line log content (programmatic)."""
    line = b"2024-01-01 10:00:00 INFO " + b"x" * 222 + b"\n"
    with open(path, "wb") as f:
        written = 0
        while written < target_bytes:
            f.write(line)
            written += len(line)
    return written


def run_benchmark():
    """Generate both fixtures, run the production worker path, print metrics."""
    from app.service import (
        MAX_OVERSIZE_UPLOAD_BYTES,
        MAX_OVERSIZE_UPLOAD_LINES,
    )
    tmp = Path(tempfile.mkdtemp(prefix="stacksift-oversize-bench-"))
    line_path = tmp / "lines-500k.log"
    byte_path = tmp / "bytes-100m.log"
    print(f"generating {line_path} ...")
    generate_line_fixture(500_000, line_path)
    print(f"generating {byte_path} ...")
    written = generate_byte_fixture(100 * 1024 * 1024 - 1024 * 1024, byte_path)
    results = {}
    for label, path in (("500k-line", line_path), ("near-100MiB", byte_path)):
        content = path.read_bytes()
        nlines = content.count(b"\n")
        start = time.perf_counter()
        data = run_supervised(path.name, content)
        elapsed = time.perf_counter() - start
        peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        ok = "error" not in data
        results[label] = ok
        print(f"--- {label} ---")
        print(f"input bytes: {len(content)}")
        print(f"line count: {nlines}")
        print(f"success: {ok}")
        if not ok:
            print(f"error: {data.get('error')}: {data.get('message')}")
        print(f"wall time: {elapsed:.2f}s")
        print(f"peak child RSS: {peak_rss} KiB")
        print(f"configured timeout: {OVERSIZE_EXECUTION_TIMEOUT_SECONDS}s")
        print(f"configured memory ceiling: {OVERSIZE_MEMORY_LIMIT_BYTES} bytes")
        print(f"oversize ceilings: {MAX_OVERSIZE_UPLOAD_BYTES} bytes / "
              f"{MAX_OVERSIZE_UPLOAD_LINES} lines")
    for path in (line_path, byte_path):
        try:
            os.unlink(path)
        except OSError:
            pass
    try:
        os.rmdir(tmp)
    except OSError:
        pass
    if not all(results.values()):
        print("BENCHMARK FAILED")
        return 1
    print("BENCHMARK OK")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", action="store_true",
                        help="run the oversize benchmark (default: show help)")
    args = parser.parse_args(argv)
    if not args.benchmark:
        parser.print_help()
        return 2
    return run_benchmark()


if __name__ == "__main__":
    sys.exit(main())


# --- pytest tests (cheap; the benchmark itself is NOT run by pytest) ---------

def test_benchmark_constants_are_configurable_candidates():
    # T1: named, configurable constants — not hardcoded promises.
    assert OVERSIZE_EXECUTION_TIMEOUT_SECONDS == 60
    assert OVERSIZE_MEMORY_LIMIT_BYTES == 512 * 1024 * 1024


def test_benchmark_fixture_generators(tmp_path):
    line_path = tmp_path / "lines.log"
    generate_line_fixture(1000, line_path)
    assert line_path.read_bytes().count(b"\n") == 1000
    byte_path = tmp_path / "bytes.log"
    written = generate_byte_fixture(1024 * 1024, byte_path)
    assert written >= 1024 * 1024
    assert byte_path.stat().st_size == written


def test_worker_small_supervised_run_via_benchmark_path():
    line = b"2024-01-01 10:00:00 INFO heartbeat ok\n"
    data = run_supervised("bench.log", line * 60000)
    assert "error" not in data, data
    assert data["results"]["level_counts"]["INFO"] == 60000
