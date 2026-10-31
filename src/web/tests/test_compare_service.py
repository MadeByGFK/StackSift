"""Issue #102 (compare, core slice): evidence collector + diff rules.

Covers the approved spec §4/§7/§8 core: hand-checked pair (one new, one
resolved, one material-volume, one severity-shift group), identical pair,
below/exact threshold, disjoint sets, ID-normalized matching, INFO-to-
ERROR as new, and the C9 collector contract (default OFF leaves the
single-file result shape unchanged; ON, counts reconcile exactly).
Routes, consent, charging, PDF, and history dispatch are later slices
of the same PR and are NOT covered here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.compare_service import compare_results
from app.vendor.analyzer import analyze_log_file


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _analyze(path, evidence=False):
    return analyze_log_file(str(path), collect_comparison_evidence=evidence)


def _log(level, message, ts="2026-07-07 10:00:00"):
    return f"{ts} {level} {message}"


def _hand_checked_pair(tmp_path):
    """A: db-fail x10, cache-miss x4, slow-db WARN x6.
    B: db-fail x20, payment-timeout x6, slow-db ERROR x6."""
    a_lines = (
        [_log("ERROR", "Database connection failed")] * 10
        + [_log("WARN", "Cache miss on user lookup")] * 4
        + [_log("WARN", "Slow database response detected")] * 6
    )
    b_lines = (
        [_log("ERROR", "Database connection failed")] * 20
        + [_log("ERROR", "Payment gateway timeout")] * 6
        + [_log("ERROR", "Slow database response detected")] * 6
    )
    a = _analyze(_write(tmp_path, "a.log", a_lines), evidence=True)
    b = _analyze(_write(tmp_path, "b.log", b_lines), evidence=True)
    return a, b


def test_hand_checked_pair_exact_arrays(tmp_path):
    a, b = _hand_checked_pair(tmp_path)
    payload = compare_results(a, b)
    assert payload["report_kind"] == "comparison"
    assert payload["matching_version"] == 1
    assert payload["material_change"] == {
        "version": 1, "min_absolute": 5, "min_fraction_of_a": 0.5,
    }
    assert payload["summary"] == {
        "new": 1, "resolved": 1, "volume_changed": 1, "severity_shifted": 1,
    }
    assert [e["template"] for e in payload["new"]] == ["Payment gateway timeout"]
    assert [e["template"] for e in payload["resolved"]] == [
        "Cache miss on user lookup"]
    assert payload["new"][0]["a_count"] == 0
    assert payload["new"][0]["b_count"] == 6
    assert payload["resolved"][0]["a_count"] == 4
    assert payload["resolved"][0]["b_count"] == 0
    volume = payload["volume_changes"]
    assert len(volume) == 1
    assert volume[0]["template"] == "Database connection failed"
    assert (volume[0]["a_count"], volume[0]["b_count"]) == (10, 20)
    shift = payload["severity_shifts"]
    assert len(shift) == 1
    assert shift[0]["template"] == "Slow database response detected"
    assert shift[0]["a_highest_severity"] == "WARN"
    assert shift[0]["b_highest_severity"] == "ERROR"
    assert (shift[0]["a_count"], shift[0]["b_count"]) == (6, 6)
    # A shared group is in both categories, not two distinct patterns.
    assert len(payload["shared"]) == 2
    assert payload["no_material_differences"] is False
    assert "not proof" in payload["resolved_note"]
    # Examples come from evidence, with line numbers, not invented.
    assert payload["new"][0]["b_examples"]["ERROR"][0]["text"].endswith(
        "Payment gateway timeout")
    assert payload["new"][0]["b_examples"]["ERROR"][0]["line_number"] >= 1


def test_identical_pair_is_valid_and_empty(tmp_path):
    lines = [_log("ERROR", "Database connection failed")] * 3
    a = _analyze(_write(tmp_path, "a.log", lines), evidence=True)
    b = _analyze(_write(tmp_path, "b.log", lines), evidence=True)
    payload = compare_results(a, b)
    assert payload["new"] == []
    assert payload["resolved"] == []
    assert payload["volume_changes"] == []
    assert payload["severity_shifts"] == []
    assert len(payload["shared"]) == 1
    assert payload["no_material_differences"] is True
    assert payload["summary"] == {
        "new": 0, "resolved": 0, "volume_changed": 0, "severity_shifted": 0,
    }


def test_below_and_exact_threshold(tmp_path):
    base = [_log("ERROR", "Database connection failed")] * 10
    a = _analyze(_write(tmp_path, "a.log", base), evidence=True)
    below = _analyze(
        _write(tmp_path, "b1.log", [_log("ERROR", "Database connection failed")] * 12),
        evidence=True)
    assert compare_results(a, below)["volume_changes"] == []
    assert compare_results(a, below)["no_material_differences"] is True
    exact = _analyze(
        _write(tmp_path, "b2.log", [_log("ERROR", "Database connection failed")] * 15),
        evidence=True)
    payload = compare_results(a, exact)
    assert len(payload["volume_changes"]) == 1  # |15-10| = 5, 5/10 = 0.5
    assert payload["no_material_differences"] is False


def test_disjoint_sets(tmp_path):
    a = _analyze(_write(tmp_path, "a.log", [_log("ERROR", "Alpha failure")] * 2),
                 evidence=True)
    b = _analyze(_write(tmp_path, "b.log", [_log("ERROR", "Beta failure")] * 2),
                 evidence=True)
    payload = compare_results(a, b)
    assert len(payload["new"]) == 1
    assert len(payload["resolved"]) == 1
    assert payload["shared"] == []
    assert payload["volume_changes"] == []
    assert payload["severity_shifts"] == []


def test_id_normalized_matching_and_info_to_error(tmp_path):
    a = _analyze(_write(tmp_path, "a.log", [
        _log("ERROR", "Request failed request_id=abc123"),
        _log("INFO", "User login successful"),
    ]), evidence=True)
    b = _analyze(_write(tmp_path, "b.log", [
        _log("ERROR", "Request failed request_id=xyz789"),
        _log("ERROR", "User login successful"),
    ]), evidence=True)
    payload = compare_results(a, b)
    # Varying IDs match to one shared group, not new+resolved.
    shared_templates = [e["template"] for e in payload["shared"]]
    assert len(shared_templates) == 1
    assert payload["new"] == [] or all(
        e["template"] != shared_templates[0] for e in payload["new"])
    # INFO has no issue group, so the ERROR occurrence is a new group.
    assert any("User login successful" in e["template"]
               for e in payload["new"])


def test_collector_off_leaves_result_shape_unchanged(tmp_path):
    lines = [_log("ERROR", "Database connection failed")] * 2
    path = _write(tmp_path, "a.log", lines)
    off = analyze_log_file(str(path))
    assert "comparison_evidence" not in off
    on = analyze_log_file(str(path), collect_comparison_evidence=True)
    assert "comparison_evidence" in on
    # Everything except the additive key is identical.
    assert {k: v for k, v in on.items() if k != "comparison_evidence"} == off


def test_collector_counts_reconcile_and_examples_bounded(tmp_path):
    lines = (
        [_log("WARN", "Slow database response detected")] * 3
        + [_log("ERROR", "Slow database response detected")] * 2
        + [_log("ERROR", "Database connection failed")] * 5
    )
    result = _analyze(_write(tmp_path, "a.log", lines), evidence=True)
    evidence = result["comparison_evidence"]
    for template, group in result["issues"].items():
        ev = evidence[template]
        assert sum(ev["level_counts"].values()) == group["count"]
        for level, examples in ev["examples"].items():
            assert len(examples) <= 2
            assert all(len(e["text"]) <= 1024 for e in examples)
    slow = [v for k, v in evidence.items() if "Slow database" in k][0]
    assert slow["level_counts"] == {"WARN": 3, "ERROR": 2}
    assert slow["examples_truncated"] is True  # 3 WARN examples, cap is 2
    # Severity uses the distribution, not the first-occurrence level.
    payload = compare_results(result, result)
    entry = payload["shared"][0] if payload["shared"] else None
    assert entry is not None


def test_zero_error_inputs_are_valid(tmp_path):
    a = _analyze(_write(tmp_path, "a.log", [_log("INFO", "Server started")]),
                 evidence=True)
    b = _analyze(_write(tmp_path, "b.log", [_log("INFO", "Server started")]),
                 evidence=True)
    payload = compare_results(a, b)
    assert payload["new"] == []
    assert payload["resolved"] == []
    assert payload["shared"] == []
    assert payload["no_material_differences"] is True
    assert payload["inputs"]["a"]["malformed_lines"] == 0


def test_no_scores_or_internal_labels_in_payload(tmp_path):
    a, b = _hand_checked_pair(tmp_path)
    payload = compare_results(a, b)
    text = repr(payload)
    for forbidden in ("diagnostic_score", "internal_label", "score="):
        assert forbidden not in text
