"""Issue #106 Stage 1 (core, CLI copy): F01/F04/F05 + evidence contract.

Mirrors src/web/tests/test_deep_dive_core.py and
test_deep_dive_evidence.py for the CLI analyzer (stacksift.analyzer);
both analyzer copies carry the identical Stage 1 contract. Every test
must FAIL on the pre-#106 tree and PASS after Stage 1.
"""
from stacksift.analyzer import analyze_log_file, analyze_path, normalize_issue


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _log(level, message, service="api"):
    return f"2026-10-11 12:00:00.100 {level} [{service}] {message}"


def test_cli_f01_bare_order_ids_group_without_merging_http_statuses(tmp_path):
    lines = (
        [_log("ERROR", f"Payment failed for order {58291 + 137 * i}: card declined",
              "payments") for i in range(10)]
        + [_log("ERROR", "Payment failed for order 58291: insufficient funds",
                "payments")]
        + [_log("ERROR", "Upstream error status=500 for checkout", "proxy")] * 2
        + [_log("ERROR", "Upstream error status=503 for checkout", "proxy")] * 2
        + [_log("ERROR", "Connection to db-01 refused", "db")]
        + [_log("ERROR", "Connection to db-02 refused", "db")]
    )
    issues = analyze_log_file(str(_write(tmp_path, "f01.log", lines)))["issues"]
    payment = [t for t in issues if t.startswith("Payment failed for order")]
    assert payment == ["Payment failed for order <id>: card declined",
                       "Payment failed for order <id>: insufficient funds"]
    assert issues[payment[0]]["count"] == 10
    assert issues[payment[1]]["count"] == 1
    assert sorted(t for t in issues if t.startswith("Upstream error")) == [
        "Upstream error status=500 for checkout",
        "Upstream error status=503 for checkout",
    ]
    assert sorted(t for t in issues if t.startswith("Connection to db-")) == [
        "Connection to db-01 refused",
        "Connection to db-02 refused",
    ]


def test_cli_f04_group_severity_is_peak_independent_of_order(tmp_path):
    msg = "Connection pool exhausted pool=primary active=50 max_connections=50"
    escalating = ([_log("WARN", msg, "db")] * 3
                  + [_log("ERROR", msg, "db")] * 4
                  + [_log("CRITICAL", msg, "db")] * 2)
    result = analyze_log_file(str(_write(tmp_path, "up.log", escalating)))
    (template, group), = result["issues"].items()
    assert group["count"] == 9
    assert group["level"] == "CRITICAL"
    assert result["level_counts"] == {"WARN": 3, "ERROR": 4, "CRITICAL": 2}

    subdir = tmp_path / "multi"
    subdir.mkdir()
    _write(subdir, "a.log", [_log("WARN", msg, "db")] * 2)
    _write(subdir, "b.log", [_log("CRITICAL", msg, "db")])
    combined = analyze_path(str(subdir))
    (ctemplate, cgroup), = combined["issues"].items()
    assert ctemplate == template
    assert cgroup["count"] == 3
    assert cgroup["level"] == "CRITICAL"


def test_cli_f05_wrapper_and_bare_cause_share_identity_preserving_occurrences(
        tmp_path):
    wrapped = _log("ERROR", "Request handler failed: DatabaseError: "
                            "connection to db-01 refused")
    bare = _log("ERROR", "DatabaseError: connection to db-01 refused", "db")
    lines = [wrapped, bare] * 5
    result = analyze_log_file(str(_write(tmp_path, "f05.log", lines)))
    assert list(result["issues"]) == [
        "DatabaseError: connection to db-01 refused"]
    assert result["issues"][
        "DatabaseError: connection to db-01 refused"]["count"] == 10
    assert result["parsed_lines"] == 10

    wrapped_timeout = _log(
        "ERROR", "Request handler failed: DatabaseError: "
                 "connection to db-01 timed out")
    result = analyze_log_file(str(_write(
        tmp_path, "f05b.log", lines + [wrapped_timeout] * 3)))
    assert sorted(result["issues"]) == [
        "DatabaseError: connection to db-01 refused",
        "DatabaseError: connection to db-01 timed out",
    ]
    assert normalize_issue("Request handler failed: something went wrong") == \
        "Request handler failed: something went wrong"


def test_cli_diagnostic_evidence_present_and_maps_to_groups(tmp_path):
    wrapped = _log("ERROR", "Request handler failed: DatabaseError: "
                            "connection to db-01 refused")
    bare = _log("ERROR", "DatabaseError: connection to db-01 refused", "db")
    lines = [wrapped, bare] * 3
    path = _write(tmp_path, "ev.log", lines)
    result = analyze_log_file(str(path))
    evidence = result["diagnostic_evidence"]
    assert evidence["schema_version"] == 1
    assert evidence["grouping_version"]
    assert evidence["coordinate"] == "analysis line"
    assert set(evidence["groups"]) == set(result["issues"])
    root = evidence["groups"]["DatabaseError: connection to db-01 refused"]
    assert root["level_counts"] == {"ERROR": 6}
    assert root["peak_level"] == "ERROR"
    texts = [e["text"] for e in root["excerpts"]]
    assert any("Request handler failed:" in t for t in texts)
    assert any("Request handler failed:" not in t for t in texts)
    for excerpt in root["excerpts"]:
        assert excerpt["text"] == lines[excerpt["analysis_line_number"] - 1]
    # Merged (analyze_path) evidence reconciles with merged counts.
    combined = analyze_path(str(tmp_path))
    merged = combined["diagnostic_evidence"]["groups"][
        "DatabaseError: connection to db-01 refused"]
    assert merged["level_counts"] == {"ERROR": 6}
