"""Issue #106 Stage 1 (evidence): retained diagnostic-evidence capture.

New standard analyses retain a versioned ``diagnostic_evidence``
contract in the analyzer result (and therefore in the stored service
payload): per-group observed severity counts plus bounded, redacted
excerpts that map to the corrected issue key and an actual processed
analysis line. These tests must FAIL on the pre-#106 tree (the key did
not exist) and PASS after Stage 1.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.vendor.analyzer as vendor_analyzer
from app.service import analyze_upload
from app.vendor.analyzer import analyze_log_file


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _log(level, message, service="api", second=0):
    return f"2026-10-11 12:00:{second:02d}.100 {level} [{service}] {message}"


_F05_LINES = [
    _log("ERROR", "Request handler failed: DatabaseError: "
                  "connection to db-01 refused", second=0),
    _log("ERROR", "DatabaseError: connection to db-01 refused", "db", 3),
    _log("ERROR", "Request handler failed: DatabaseError: "
                  "connection to db-01 refused", second=9),
    _log("ERROR", "DatabaseError: connection to db-01 refused", "db", 12),
]
_F04_MSG = "Connection pool exhausted pool=primary active=50 max_connections=50"


def test_evidence_versioned_and_maps_to_corrected_keys(tmp_path):
    lines = _F05_LINES + [
        _log("WARN", _F04_MSG, "db", 20),
        _log("CRITICAL", _F04_MSG, "db", 26),
    ]
    path = _write(tmp_path, "ev.log", lines)
    result = analyze_log_file(str(path))
    evidence = result["diagnostic_evidence"]

    assert evidence["schema_version"] == 1
    assert evidence["grouping_version"]
    # Coordinates are labeled "analysis line", never claimed as the
    # original physical source lines.
    assert evidence["coordinate"] == "analysis line"
    # The F05 group has 4 occurrences but the per-severity excerpt cap
    # is 2, so sampling truncation is honestly disclosed.
    assert evidence["truncated"] is True
    assert evidence["groups_truncated"] is False

    # Every group maps to a corrected issue key, and its observed
    # severity counts reconcile exactly with the group count.
    assert set(evidence["groups"]) == set(result["issues"])
    for template, group in evidence["groups"].items():
        assert sum(group["level_counts"].values()) == \
            result["issues"][template]["count"]
        for excerpt in group["excerpts"]:
            # The excerpt is an actual processed line of this analysis.
            actual = lines[excerpt["analysis_line_number"] - 1]
            assert excerpt["text"] == actual
            assert excerpt["timestamp"]
            assert excerpt["service"]

    root = evidence["groups"]["DatabaseError: connection to db-01 refused"]
    # Both the wrapped and the bare variant are retained as excerpts, so
    # the F05 grouping correction does not erase its own support.
    texts = [e["text"] for e in root["excerpts"]]
    assert any("Request handler failed:" in t for t in texts)
    assert any("Request handler failed:" not in t for t in texts)

    pool_template = [t for t in evidence["groups"]
                     if "Connection pool exhausted" in t][0]
    pool = evidence["groups"][pool_template]
    assert pool["level_counts"] == {"WARN": 1, "CRITICAL": 1}
    assert pool["peak_level"] == "CRITICAL"
    # The peak-severity example is captured.
    assert any(e["level"] == "CRITICAL" for e in pool["excerpts"])

    # Evidence IDs are stable: a re-run over the same input produces
    # byte-identical evidence.
    again = analyze_log_file(str(path))["diagnostic_evidence"]
    assert again == evidence
    ids = [e["evidence_id"] for g in evidence["groups"].values()
           for e in g["excerpts"]]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("ev-") for i in ids)


def test_evidence_service_path_retains_redacted_excerpts():
    secret = "hunter2secret"
    lines = [
        _log("ERROR", f"DatabaseError: connection failed password={secret}",
             "db", 0),
        _log("ERROR", f"DatabaseError: connection failed password={secret}",
             "db", 3),
    ]
    out = analyze_upload("ev.log", ("\n".join(lines) + "\n").encode())
    assert "error" not in out, out
    evidence = out["results"]["diagnostic_evidence"]
    assert set(evidence["groups"]) == set(out["results"]["issues"])
    # Excerpts come from the redacted analysis representation: the
    # secret never appears anywhere in the retained evidence.
    assert secret not in json.dumps(evidence)
    texts = [e["text"] for g in evidence["groups"].values()
             for e in g["excerpts"]]
    assert texts and all("[REDACTED]" in t for t in texts)


def test_evidence_truncation_bounds_and_group_cap(tmp_path):
    # Per-severity excerpt cap: 5 occurrences, at most 2 excerpts.
    lines = [_log("ERROR", "Database connection failed", "db", i)
             for i in range(5)]
    result = analyze_log_file(str(_write(tmp_path, "cap.log", lines)))
    group = result["diagnostic_evidence"]["groups"][
        "Database connection failed"]
    assert group["level_counts"] == {"ERROR": 5}
    assert len(group["excerpts"]) == 2
    assert group["excerpts_truncated"] is True
    assert result["diagnostic_evidence"]["truncated"] is True

    # Over-long lines are clipped to 1,024 chars and flagged per excerpt.
    long_line = _log("ERROR", "Failure " + "x" * 2000, "db", 0)
    result = analyze_log_file(str(_write(tmp_path, "long.log", [long_line])))
    group = list(result["diagnostic_evidence"]["groups"].values())[0]
    (excerpt,) = group["excerpts"]
    assert len(excerpt["text"]) == 1024
    assert excerpt["text_truncated"] is True

    # Group cap: the standard analysis still succeeds with all issue
    # groups, while retained evidence is bounded and honestly flagged.
    many = [_log("ERROR", f"Distinct failure number {i} happened", "db", 0)
            for i in range(1005)]
    result = analyze_log_file(str(_write(tmp_path, "many.log", many)))
    assert len(result["issues"]) == 1005
    evidence = result["diagnostic_evidence"]
    assert len(evidence["groups"]) <= 1000
    assert evidence["groups_truncated"] is True
    assert evidence["truncated"] is True


def test_evidence_serialized_size_bound_enforced(tmp_path, monkeypatch):
    lines = [
        _log("ERROR", "Alpha failure with a reasonably long message body "
                      "to carry serialized weight in evidence", "db", i)
        for i in range(3)
    ] + [
        _log("ERROR", "Beta failure with a reasonably long message body "
                      "to carry serialized weight in evidence", "db", i)
        for i in range(3)
    ]
    path = _write(tmp_path, "size.log", lines)
    monkeypatch.setattr(
        vendor_analyzer, "MAX_DIAGNOSTIC_EVIDENCE_BYTES", 1200)
    result = analyze_log_file(str(path))
    evidence = result["diagnostic_evidence"]
    assert len(json.dumps(evidence).encode("utf-8")) <= 1200
    assert evidence["truncated"] is True
    # The analysis itself is untouched by the evidence trim.
    assert sum(g["count"] for g in result["issues"].values()) == 6
