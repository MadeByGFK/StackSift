"""Issue #106 Stage 1 — PR #137 Codex remediation (CLI analyzer copy).

Regression tests for the four Codex findings on PR #137. Every test
must FAIL on the pre-remediation tree (75003371) and PASS after:
1. P1: _enforce_evidence_size re-serialized the whole evidence dict
   for every excerpt removed (analysis_timeout on multi-MB inputs).
2. P2: CLI-path evidence excerpts retained unredacted secrets.
3. P2: analyze_path retained every file's complete evidence artifact.
4. P2: merged severity metadata was lost across per-file group
   clipping, so retained evidence contradicted the combined issue.
5. P2 (finding 5, on the remediation head dc1415a): the F01
   bare-order normalization also rewrote ``byte order <n>``, merging
   distinct byte-order property values into one group.
The vendored copy carries the identical contract:
src/web/tests/test_deep_dive_remediation.py.
"""
import gc
import json
import weakref

import stacksift.analyzer as analyzer
from stacksift.analyzer import analyze_log_file, analyze_path, normalize_issue


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _log(level, message, service="api"):
    return f"2026-10-11 12:00:00.100 {level} [{service}] {message}"


# --- Finding 1 (P1): batched size enforcement ----------------------------

def test_size_enforcement_does_not_reserialize_per_excerpt(
        tmp_path, monkeypatch):
    # Codex's timeout shape, scaled to stay CI-fast: many distinct
    # groups, 2 occurrences per severity (the excerpt cap), and
    # backslash-heavy messages (escaping inflates serialized size).
    lines = []
    for i in range(300):
        msg = f"Failure cluster{i} " + "\\\\node\\\\share" * 4
        for level in ("ERROR", "CRITICAL"):
            lines += [_log(level, msg, "db"), _log(level, msg, "db")]
    path = _write(tmp_path, "big.log", lines)
    monkeypatch.setattr(analyzer, "MAX_DIAGNOSTIC_EVIDENCE_BYTES", 150_000)

    dumps_calls = {"n": 0}
    real_dumps = json.dumps

    def counting_dumps(obj, *args, **kwargs):
        dumps_calls["n"] += 1
        return real_dumps(obj, *args, **kwargs)

    monkeypatch.setattr(json, "dumps", counting_dumps)
    result = analyze_log_file(str(path))
    calls_during_analysis = dumps_calls["n"]
    monkeypatch.undo()

    evidence = result["diagnostic_evidence"]
    assert len(json.dumps(evidence).encode("utf-8")) <= 150_000
    assert evidence["truncated"] is True
    # Batched trimming serializes O(batches) times, not once per
    # removed excerpt (the pre-fix code needed ~1,000 serializations
    # of a several-hundred-KB document for this input).
    assert calls_during_analysis <= 20
    # The analysis itself is untouched by the evidence trim.
    assert sum(g["count"] for g in result["issues"].values()) == 1200


# --- Finding 2 (P2): redaction at capture ---------------------------------

_SECRET = "hunter2secret"


def test_capture_redacts_secret_omitted_from_template(tmp_path):
    # Codex's repro shape: a JSON ERROR entry whose canonical
    # template omits the message field carrying the credential. The
    # retained excerpt is the raw line — it must be redacted at
    # capture even on this direct (CLI-style) path.
    line = json.dumps({
        "timestamp": "2026-10-11T12:00:00.000Z",
        "level": "error",
        "message": f"Database failed password={_SECRET}",
        "operation": "connect",
        "service": "db",
    })
    result = analyze_log_file(str(_write(tmp_path, "json.log", [line, line])))
    assert list(result["issues"]) == ["operation=connect service=db"]
    evidence = result["diagnostic_evidence"]
    assert _SECRET not in json.dumps(evidence)
    texts = [e["text"] for g in evidence["groups"].values()
             for e in g["excerpts"]]
    assert texts and all("[REDACTED]" in t for t in texts)


def test_capture_redacts_retained_service_metadata(tmp_path):
    line = _log("ERROR", "Database failed", service=f"password={_SECRET}")
    result = analyze_log_file(str(_write(tmp_path, "svc.log", [line])))
    evidence = result["diagnostic_evidence"]
    assert _SECRET not in json.dumps(evidence)
    (group,) = evidence["groups"].values()
    (excerpt,) = group["excerpts"]
    assert excerpt["service"] == "password=[REDACTED]"


# --- Finding 3 (P2): analyze_path releases per-file evidence --------------

class _TrackedEvidence(dict):
    """dict subclass so weakrefs can observe artifact retention."""


def test_analyze_path_releases_per_file_evidence(tmp_path, monkeypatch):
    subdir = tmp_path / "multi"
    subdir.mkdir()
    for i in range(6):
        _write(subdir, f"f{i}.log",
               [_log("ERROR", f"Failure number {i} happened", "db")])

    original = analyzer.analyze_log_file
    refs = []
    alive_at_entry = []

    def spy(file_path, *args, **kwargs):
        gc.collect()
        alive_at_entry.append(sum(1 for r in refs if r() is not None))
        result = original(file_path, *args, **kwargs)
        tracked = _TrackedEvidence(result["diagnostic_evidence"])
        result["diagnostic_evidence"] = tracked
        refs.append(weakref.ref(tracked))
        return result

    monkeypatch.setattr(analyzer, "analyze_log_file", spy)
    combined = analyze_path(str(subdir))

    # At most the file currently being handed over may still be
    # alive; the pre-fix list retained ALL previous files' artifacts
    # (alive_at_entry would reach 5 by the last file).
    assert max(alive_at_entry) <= 1
    # The incremental merge is equivalent for unclipped inputs.
    assert combined["total_lines"] == 6
    merged = combined["diagnostic_evidence"]
    assert len(merged["groups"]) == 6
    for group in merged["groups"].values():
        assert group["level_counts"] == {"ERROR": 1}


# --- Finding 4 (P2): severity metadata across group clipping --------------

def test_merged_severity_metadata_survives_per_file_clipping(tmp_path):
    # Codex's repro: a.log has one WARN 'Target failure'; b.log has
    # 1,000 other groups followed by a CRITICAL 'Target failure', so
    # the group falls outside b.log's 1,000 excerpt groups.
    subdir = tmp_path / "sev"
    subdir.mkdir()
    _write(subdir, "a.log", [_log("WARN", "Target failure", "db")])
    b_lines = [_log("ERROR", f"Distinct failure number {i} happened", "db")
               for i in range(1000)]
    b_lines.append(_log("CRITICAL", "Target failure", "db"))
    _write(subdir, "b.log", b_lines)

    combined = analyze_path(str(subdir))
    issue = combined["issues"]["Target failure"]
    assert issue["count"] == 2
    assert issue["level"] == "CRITICAL"

    evidence = combined["diagnostic_evidence"]
    group = evidence["groups"]["Target failure"]
    # The merged evidence must not contradict the combined issue.
    assert group["level_counts"] == {"WARN": 1, "CRITICAL": 1}
    assert group["peak_level"] == "CRITICAL"
    # b.log contributed NO excerpt for this group (clipped whole), so
    # the excerpt flag honestly reports clipping — while the severity
    # metadata above is complete.
    assert group["excerpts_truncated"] is True
    assert evidence["severity_metadata"]["Target failure"] == {
        "level_counts": {"WARN": 1, "CRITICAL": 1},
        "peak_level": "CRITICAL",
    }

    # Single file: b.log alone retains the clipped group's severity
    # metadata even though it has no excerpt group for it.
    b_only = analyze_log_file(str(subdir / "b.log"))
    b_evidence = b_only["diagnostic_evidence"]
    assert "Target failure" not in b_evidence["groups"]
    assert b_evidence["groups_truncated"] is True
    assert b_evidence["severity_metadata"]["Target failure"] == {
        "level_counts": {"CRITICAL": 1},
        "peak_level": "CRITICAL",
    }


# --- Finding 5 (P2): byte order is a property, not an identifier ----------

def test_f01_byte_order_values_are_not_bare_order_ids():
    # Codex's repro: the number after "byte order" IS the property
    # (1234 vs 4321 are distinct byte-ordering encodings), so the
    # F01 bare-order rule must preserve it verbatim — pre-fix both
    # lines collapsed to 'Unsupported byte order <id>'.
    assert normalize_issue("Unsupported byte order 1234") == \
        "Unsupported byte order 1234"
    assert normalize_issue("Unsupported byte order 4321") == \
        "Unsupported byte order 4321"
    assert normalize_issue("Unsupported byte order 1234") != \
        normalize_issue("Unsupported byte order 4321")
    # Positive control: the intended F01 case still normalizes, so
    # distinct volatile payment order IDs share one template.
    assert normalize_issue(
        "Payment failed for order 58291: insufficient funds") == \
        "Payment failed for order <id>: insufficient funds"
    assert normalize_issue(
        "Payment failed for order 69420: insufficient funds") == \
        "Payment failed for order <id>: insufficient funds"


def test_f01_byte_order_groups_stay_distinct_while_payment_orders_group(
        tmp_path):
    lines = (
        [_log("ERROR", "Unsupported byte order 1234", "codec")] * 2
        + [_log("ERROR", "Unsupported byte order 4321", "codec")] * 2
        + [_log("ERROR", "Payment failed for order 58291: insufficient funds",
                "payments")]
        + [_log("ERROR", "Payment failed for order 69420: insufficient funds",
                "payments")]
    )
    issues = analyze_log_file(str(_write(tmp_path, "f01b.log", lines)))["issues"]
    # Two distinct byte-order groups (pre-fix they merged into one
    # 'Unsupported byte order <id>' group of 4)...
    assert issues["Unsupported byte order 1234"]["count"] == 2
    assert issues["Unsupported byte order 4321"]["count"] == 2
    # ...while the two volatile payment order IDs still group as one.
    assert issues["Payment failed for order <id>: insufficient funds"][
        "count"] == 2
    assert len(issues) == 3
