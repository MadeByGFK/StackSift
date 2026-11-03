"""Issue #106 Stage 1 (core): F01/F04/F05 grouping + severity fixes.

These tests cover the WEB vendored analyzer (app.vendor.analyzer); the
CLI copy (stacksift.analyzer) carries the identical contract and is
covered by tests/test_analyzer_106_stage1.py at the repository root.

Every test here is a regression test for a frozen #60 benchmark miss
class and must FAIL on the pre-#106 tree and PASS after Stage 1:
- F01: volatile bare order IDs split one payment failure into singletons.
- F04: a group's recorded level was the first-seen severity, so an
  escalating failure stayed WARN.
- F05: a request-handler wrapper line formed a second group beside its
  bare root-cause form.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.vendor.analyzer import analyze_log_file, analyze_path, normalize_issue


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _log(level, message, service="api"):
    return f"2026-10-11 12:00:00.100 {level} [{service}] {message}"


def test_f01_bare_order_ids_group_without_merging_http_statuses(tmp_path):
    lines = (
        [_log("ERROR", f"Payment failed for order {58291 + 137 * i}: card declined",
              "payments") for i in range(10)]
        # Negative: a different failure reason after the same order
        # pattern is a materially different message — stays separate.
        + [_log("ERROR", "Payment failed for order 58291: insufficient funds",
                "payments")]
        # Negative: HTTP status is diagnostically meaningful — 500 and
        # 503 upstreams stay separate groups.
        + [_log("ERROR", "Upstream error status=500 for checkout", "proxy")] * 2
        + [_log("ERROR", "Upstream error status=503 for checkout", "proxy")] * 2
        # Negative: hostname/node identity is preserved.
        + [_log("ERROR", "Connection to db-01 refused", "db")]
        + [_log("ERROR", "Connection to db-02 refused", "db")]
    )
    result = analyze_log_file(str(_write(tmp_path, "f01.log", lines)))
    issues = result["issues"]

    payment = [t for t in issues if t.startswith("Payment failed for order")]
    assert payment == ["Payment failed for order <id>: card declined",
                       "Payment failed for order <id>: insufficient funds"]
    assert issues[payment[0]]["count"] == 10
    assert issues[payment[1]]["count"] == 1
    assert normalize_issue("Payment failed for order 58291: card declined") == \
        "Payment failed for order <id>: card declined"

    upstream = sorted(t for t in issues if t.startswith("Upstream error"))
    assert upstream == ["Upstream error status=500 for checkout",
                        "Upstream error status=503 for checkout"]
    nodes = sorted(t for t in issues if t.startswith("Connection to db-"))
    assert nodes == ["Connection to db-01 refused",
                     "Connection to db-02 refused"]


def test_f04_group_severity_is_peak_independent_of_order(tmp_path):
    msg = "Connection pool exhausted pool=primary active=50 max_connections=50"
    escalating = (
        [_log("WARN", msg, "db")] * 3
        + [_log("ERROR", msg, "db")] * 4
        + [_log("CRITICAL", msg, "db")] * 2
    )
    result = analyze_log_file(str(_write(tmp_path, "up.log", escalating)))
    (template, group), = result["issues"].items()
    assert group["count"] == 9
    assert group["level"] == "CRITICAL"
    # Global counts are unchanged and source events are not relabeled.
    assert result["level_counts"] == {"WARN": 3, "ERROR": 4, "CRITICAL": 2}

    # Reverse order (peak first) records the same peak.
    deescalating = (
        [_log("CRITICAL", msg, "db")] * 2
        + [_log("ERROR", msg, "db")] * 4
        + [_log("WARN", msg, "db")] * 3
    )
    result = analyze_log_file(str(_write(tmp_path, "down.log", deescalating)))
    (template2, group2), = result["issues"].items()
    assert template2 == template
    assert group2["level"] == "CRITICAL"
    assert group2["count"] == 9

    # Cross-file merge in analyze_path also takes the peak.
    subdir = tmp_path / "multi"
    subdir.mkdir()
    _write(subdir, "a.log", [_log("WARN", msg, "db")] * 2)
    _write(subdir, "b.log", [_log("CRITICAL", msg, "db")])
    combined = analyze_path(str(subdir))
    (ctemplate, cgroup), = combined["issues"].items()
    assert ctemplate == template
    assert cgroup["count"] == 3
    assert cgroup["level"] == "CRITICAL"


def test_f05_wrapper_and_bare_cause_share_identity_preserving_occurrences(tmp_path):
    wrapped = _log("ERROR", "Request handler failed: DatabaseError: "
                            "connection to db-01 refused")
    bare = _log("ERROR", "DatabaseError: connection to db-01 refused", "db")
    lines = [wrapped, bare] * 5
    result = analyze_log_file(str(_write(tmp_path, "f05.log", lines)))
    issues = result["issues"]
    assert list(issues) == ["DatabaseError: connection to db-01 refused"]
    # Grouping is NOT deduplication: all ten occurrences are preserved.
    assert issues["DatabaseError: connection to db-01 refused"]["count"] == 10
    assert result["parsed_lines"] == 10

    # Negative: refused vs timed out stay separate, wrapped or not.
    wrapped_timeout = _log(
        "ERROR", "Request handler failed: DatabaseError: "
                 "connection to db-01 timed out")
    result = analyze_log_file(str(_write(
        tmp_path, "f05b.log", lines + [wrapped_timeout] * 3)))
    assert sorted(result["issues"]) == [
        "DatabaseError: connection to db-01 refused",
        "DatabaseError: connection to db-01 timed out",
    ]
    assert result["issues"][
        "DatabaseError: connection to db-01 timed out"]["count"] == 3

    # Negative: the wrapper is stripped ONLY before a recognized
    # exception-bearing cause; other wrapped text keeps its identity and
    # other wrappers are never stripped.
    assert normalize_issue("Request handler failed: something went wrong") == \
        "Request handler failed: something went wrong"
    assert normalize_issue(
        "Cron job failed: DatabaseError: connection to db-01 refused"
    ) == "Cron job failed: DatabaseError: connection to db-01 refused"
