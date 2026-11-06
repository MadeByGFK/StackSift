"""Issue #162: Investigation Brief (premium synthesis front section).

Spec: issue-162-spec.md as amended by Amendment A1 (all 8 Codex
spec-challenge findings accepted). Teeth discipline per A1/P2-7:
new-feature assertions FAIL on the pre-build tree (d632c052, where
GENERATOR_VERSION is "106-stage2-v1" and artifacts carry no brief);
compatibility / "unchanged" assertions are regression gates that
pass on both trees and are labelled as such in their docstrings.
"""

import copy
import hashlib
import io
import json
import re
import time
import uuid
import zlib
from datetime import datetime, timedelta, timezone

import pytest

from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2a_regressions import env  # noqa: F401
from test_phase2b_paid_e2e import paid_env  # noqa: F401
from test_structured_export_e2e import _balance, _ops, _session_csrf, _setup
from test_phase2b_reports_pdf import _login, _signup_and_verify
from app import credits as C
from app import deep_dive as dd
from app.sample_data import SAMPLE_FILENAME, SAMPLE_LOG


# --- helpers -----------------------------------------------------------------

def _sample_payload():
    from app.service import analyze_upload
    data = analyze_upload(SAMPLE_FILENAME, SAMPLE_LOG.encode())
    assert "error" not in data, data
    return data


def _sample_artifact():
    return dd.build_deep_dive(_sample_payload())


def _pdf_text(pdf_bytes):
    """Real-PDF text extraction. On the post-#160 designed PDFs the
    text is subset-TTF glyph IDs, so extraction goes through the
    ToUnicode-aware extractor from the #160 suite; whitespace is
    collapsed so substring assertions match the old Tj-join shape."""
    from test_issue160_designed_reports import extract_pdf_text
    return re.sub(r"\s+", " ", extract_pdf_text(pdf_bytes))


def _synthetic_payload(group_specs, *, diagnostic_issue="present",
                       filename="synthetic.log"):
    """Minimal eligible payload. group_specs: list of dicts with
    template/count/level/services/first_seen/last_seen/excerpts/
    level_counts. Excerpts default to [] (severity-only coverage)."""
    issues = {}
    groups_evidence = {}
    metadata = {}
    for spec in group_specs:
        template = spec["template"]
        issues[template] = {
            "level": spec.get("level", "ERROR"),
            "count": spec.get("count", 1),
            "services": spec.get("services", []),
            "first_seen": spec.get("first_seen"),
            "last_seen": spec.get("last_seen", spec.get("first_seen")),
        }
        level_counts = spec.get("level_counts") or {
            spec.get("level", "ERROR"): spec.get("count", 1)}
        excerpts = spec.get("excerpts")
        if excerpts is None:
            metadata[template] = {
                "level_counts": level_counts,
                "peak_level": spec.get("level", "ERROR")}
        else:
            groups_evidence[template] = {
                "level_counts": level_counts,
                "peak_level": spec.get("level", "ERROR"),
                "excerpts": excerpts,
                "excerpts_truncated": False,
            }
    payload = {
        "filename": filename,
        "first_seen": "2026-01-01T00:00:00.000Z",
        "last_seen": "2026-01-02T00:00:00.000Z",
        "health": {"label": "Warning", "color": "yellow"},
        "diagnostic_explanation": ["WARN severity"],
        "results": {
            "total_lines": 10, "parsed_lines": 10, "malformed_lines": 0,
            "level_counts": {"ERROR": 10},
            "issues": issues,
            "diagnostic_evidence": {
                "schema_version": 1, "grouping_version": "162-test-v1",
                "coordinate": "analysis line",
                "groups": groups_evidence,
                "severity_metadata": metadata,
                "groups_truncated": False, "truncated": False,
            },
        },
        "sorted_issues": [[s["template"], issues[s["template"]]]
                          for s in group_specs],
    }
    if diagnostic_issue == "present":
        lead = group_specs[0]["template"]
        payload["diagnostic_issue"] = [lead, issues[lead]]
    elif diagnostic_issue == "dangling":
        payload["diagnostic_issue"] = ["no such group template", {}]
    return payload


def _excerpt(text, ts="2026-01-01T10:00:00.000Z", line=1):
    return {"evidence_id": f"ev-{line}", "analysis_line_number": line,
            "text": text, "timestamp": ts, "service": None,
            "level": "ERROR", "text_truncated": False}


def _brief_blob(artifact):
    return json.dumps(dd.public_projection(artifact)["brief"])


# --- 1. sample-log acceptance --------------------------------------------------

def test_brief_generator_version_bumped():
    assert dd.GENERATOR_VERSION == "162-brief-v1"


def test_sample_brief_lead_is_pool_exhaustion_not_circuit_breaker():
    brief = _sample_artifact()["brief"]
    assert brief["lead"]["template"] == \
        "connection pool exhausted, waiting for slot"
    summary = brief["summary"]
    assert any('The investigation lead is "connection pool exhausted, '
               'waiting for slot"' in s for s in summary)
    assert summary[-1] == dd.BRIEF_NOT_ESTABLISHED


def test_sample_brief_sequence_order_and_timestamps():
    brief = _sample_artifact()["brief"]
    entries = brief["sequence"]["entries"]
    assert brief["sequence"]["caption"] == dd.BRIEF_SEQUENCE_CAPTION
    stamps = [e["first_seen"] for e in entries]
    assert stamps == sorted(stamps)
    assert len(entries) <= 8
    joined = [(e["first_seen"], e["last_seen"]) for e in entries]
    assert any("08:31:07" in first for first, _ in joined)  # latency
    assert any("08:31:52" in first for first, _ in joined)  # pool (lead)
    db = next(e for e in entries if "Database connection timeout" in e["template"])
    assert "08:32:15" in db["first_seen"] and "08:33:19" in db["last_seen"]
    assert any("08:34:10" in first for first, _ in joined)  # first payment
    assert any("08:35:44" in first for first, _ in joined)  # circuit breaker
    order = [next(i for i, e in enumerate(entries) if needle in e["first_seen"])
             for needle in ("08:31:07", "08:31:52", "08:32:15",
                            "08:34:10", "08:35:44")]
    assert order == sorted(order)


def test_sample_brief_db_timeout_abstention_preserved():
    artifact = _sample_artifact()
    db_group = next(g for g in artifact["groups"]
                    if "Database connection timeout" in g["template"])
    assert db_group["possible_causes"][0]["text"] == dd.ABSTENTION
    # The brief never upgrades the abstention: no brief sentence
    # attributes a cause to the database-timeout group.
    blob = _brief_blob(artifact)
    assert "timeout can occur" not in blob.lower()


def test_sample_brief_no_causal_or_internal_language():
    brief = _sample_artifact()["brief"]
    blob = json.dumps(brief)
    scrubbed = blob.replace(dd.BRIEF_NOT_ESTABLISHED, "")
    for banned in ("caused by", "led to", "root cause", "recovered",
                   "Correlated:", "Possible link:", "diagnostic_explanation",
                   "evidence_refs", "_evidence_refs", "signal", "tier",
                   "score"):
        assert banned.lower() not in scrubbed.lower(), banned
    # The why-first limitation (A1/P2-5 honest form) is present.
    assert brief["why_first"]["limitation"] == dd.BRIEF_WHY_LIMITATION
    assert "investigate first" in brief["why_first"]["statement"]


def test_brief_claim_dicts_are_unwrapped_to_text():
    # A1/P1-1: internal claims are dicts; the stored brief must hold
    # plain strings, never a claim dict or its refs.
    brief = _sample_artifact()["brief"]
    assert isinstance(brief["lead"]["cause"], str)
    assert isinstance(brief["lead"]["symptom"], str)
    blob = json.dumps(brief)
    assert "evidence_refs" not in blob
    assert "'text':" not in blob and '"evidence_id"' not in blob


def test_brief_public_projection_allowlist_blocks_planted_sentinels():
    artifact = _sample_artifact()
    poisoned = copy.deepcopy(artifact)
    poisoned["brief"]["lead"]["evidence_refs"] = ["SENTINEL_REF_162"]
    poisoned["brief"]["lead"]["_evidence_refs"] = ["SENTINEL_REF_162"]
    poisoned["brief"]["summary"] = list(poisoned["brief"]["summary"]) + [
        {"text": "x", "evidence_refs": ["SENTINEL_REF_162"]}]
    poisoned["brief"]["priority_checks"][0]["digest"] = "SENTINEL_DIGEST_162"
    poisoned["brief"]["integrity_digest"] = "SENTINEL_DIGEST_162"
    projection = dd.public_projection(poisoned)
    blob = json.dumps(projection)
    assert "SENTINEL_REF_162" not in blob
    assert "SENTINEL_DIGEST_162" not in blob
    assert "evidence_refs" not in blob


def test_diagnostic_explanation_sentinel_never_reaches_brief():
    payload = _sample_payload()
    payload["diagnostic_explanation"] = [
        "SENTINEL_EXPLANATION_162: internal ranking prose"]
    artifact = dd.build_deep_dive(payload)
    assert "SENTINEL_EXPLANATION_162" not in _brief_blob(artifact)
    # ...while the same sentinel inside genuine log evidence is
    # preserved (evidence quotation is not narrator leakage).
    payload2 = _synthetic_payload([{
        "template": "DatabaseError: connection to db-01 refused",
        "count": 2, "level": "ERROR", "services": ["db"],
        "first_seen": "2026-01-01T10:00:00.000Z",
        "excerpts": [_excerpt("SENTINEL_EVIDENCE_162 genuine log line")],
    }])
    artifact2 = dd.build_deep_dive(payload2)
    assert "SENTINEL_EVIDENCE_162" in json.dumps(
        dd.public_projection(artifact2))


# --- 2. free / paid boundary ---------------------------------------------------

def test_free_surfaces_contain_no_brief():
    from app.service import render_text_report
    from app.pdf_export import generate_report_pdf
    payload = _sample_payload()
    brief = dd.build_deep_dive(payload)["brief"]
    s4 = next(s for s in brief["summary"] if "investigation lead" in s)
    for surface in (render_text_report(payload),
                    _pdf_text(generate_report_pdf(
                        json.dumps(payload, default=str), SAMPLE_FILENAME))):
        assert s4 not in surface
        assert dd.BRIEF_NOT_ESTABLISHED not in surface
        assert dd.BRIEF_SEQUENCE_CAPTION not in surface
        assert "Investigation Brief" not in surface


def test_paid_surfaces_contain_brief_and_csv_is_byte_identical():
    from app.pdf_export import generate_deep_dive_pdf
    artifact = _sample_artifact()
    projection = dd.public_projection(artifact)
    assert projection["brief"]["lead"]["template"].startswith(
        "connection pool exhausted")
    # TXT: the plain-text lines helper carries the brief lines.
    txt = "\n".join(dd.projection_text_lines(projection))
    assert "Investigation Brief" in txt
    assert dd.BRIEF_NOT_ESTABLISHED in txt
    assert dd.BRIEF_SEQUENCE_CAPTION in txt
    # PDF: REAL generate_deep_dive_pdf extraction (A1/P1-2).
    pdf_text = _pdf_text(generate_deep_dive_pdf(
        json.dumps(artifact), SAMPLE_FILENAME))
    assert "Investigation Brief" in pdf_text
    assert "connection pool exhausted" in pdf_text
    assert "08:31:07" in pdf_text and "08:35:44" in pdf_text
    # CSV: byte-identical to the same artifact with the brief removed
    # (the pre-build generator's CSV for this artifact), group table
    # only, and no copy describes CSV as containing the brief.
    stripped = copy.deepcopy(artifact)
    stripped.pop("brief")
    csv_new = dd.projection_to_csv(projection)
    csv_old = dd.projection_to_csv(dd.public_projection(stripped))
    assert csv_new == csv_old
    assert b"Investigation Brief" not in csv_new
    assert csv_new.startswith(b"template,level,count,services,first_seen,last_seen")


# --- 3. sentence-source integrity ----------------------------------------------

def test_missing_diagnostic_issue_omits_lead_without_fabrication():
    payload = _synthetic_payload([
        {"template": "DatabaseError: connection to db-01 refused",
         "count": 2, "level": "ERROR",
         "first_seen": "2026-01-01T10:00:00.000Z"},
        {"template": "Connection pool exhausted", "count": 1,
         "level": "WARN", "first_seen": "2026-01-01T10:01:00.000Z"},
    ], diagnostic_issue="absent")
    brief = dd.build_deep_dive(payload)["brief"]
    assert brief["lead"] is None and brief["why_first"] is None
    assert not any("investigation lead is" in s for s in brief["summary"])
    assert brief["summary"][-1] == dd.BRIEF_NOT_ESTABLISHED


def test_dangling_diagnostic_issue_records_limitation_no_lead():
    payload = _synthetic_payload([
        {"template": "DatabaseError: connection to db-01 refused",
         "count": 2, "level": "ERROR",
         "first_seen": "2026-01-01T10:00:00.000Z"},
    ], diagnostic_issue="dangling")
    brief = dd.build_deep_dive(payload)["brief"]
    assert brief["lead"] is None
    assert any("no matching issue group" in lim
               for lim in brief["limitations"])


def test_no_timestamps_omits_sequence_with_limitation():
    payload = _synthetic_payload([
        {"template": "DatabaseError: connection to db-01 refused",
         "count": 3, "level": "ERROR"},
    ])
    brief = dd.build_deep_dive(payload)["brief"]
    assert brief["sequence"] is None
    assert dd.BRIEF_NO_SEQUENCE_LIMITATION in brief["summary"] or \
        dd.BRIEF_NO_SEQUENCE_LIMITATION in brief["limitations"]
    blob = json.dumps(dd.public_projection(
        dd.build_deep_dive(payload))["brief"])
    assert "at None" not in blob and "around None" not in blob


def test_partial_timestamps_sequence_limitation_and_no_none_text():
    payload = _synthetic_payload([
        {"template": "DatabaseError: connection to db-01 refused",
         "count": 2, "level": "ERROR",
         "first_seen": "2026-01-01T10:00:00.000Z"},
        {"template": "Connection pool exhausted", "count": 1,
         "level": "WARN"},  # no timestamps
    ])
    brief = dd.build_deep_dive(payload)["brief"]
    assert brief["sequence"] is not None
    assert len(brief["sequence"]["entries"]) == 1
    assert dd.BRIEF_NO_TIMESTAMPS_LIMITATION in brief["limitations"]
    blob = json.dumps(brief)
    assert "at None" not in blob and "around None" not in blob


# --- 4. adversarial fixtures -----------------------------------------------------

def _cause_for(payload, template):
    artifact = dd.build_deep_dive(payload)
    group = next(g for g in artifact["groups"] if g["template"] == template)
    return group["possible_causes"][0]["text"], artifact


def test_adversarial_config_only_timeout_abstains():
    from app.service import analyze_upload
    data = analyze_upload(
        "cfg.log",
        b"2026-10-11 09:00:00 WARN Request timeout configured at 5000ms "
        b"for upstream calls\n"
        b"2026-10-11 09:01:00 WARN Request timeout configured at 5000ms "
        b"for upstream calls\n")
    cause, artifact = _cause_for(
        data, "Request timeout configured at 5000ms for upstream calls")
    assert cause == dd.ABSTENTION
    assert artifact["brief"]["lead"]["cause"] == dd.ABSTENTION


def test_adversarial_negated_timeout_abstains():
    from app.service import analyze_upload
    data = analyze_upload(
        "neg.log",
        b"2026-10-11 09:00:00 ERROR Database query finished with no "
        b"timeout recorded\n"
        b"2026-10-11 09:01:00 ERROR Database query finished with no "
        b"timeout recorded\n")
    cause, artifact = _cause_for(
        data, "Database query finished with no timeout recorded")
    assert cause == dd.ABSTENTION
    assert artifact["brief"]["lead"]["cause"] == dd.ABSTENTION


def test_adversarial_payment_policy_refused_abstains():
    from app.service import analyze_upload
    data = analyze_upload(
        "policy.log",
        b"2026-10-11 09:00:00 ERROR Payment refused by fraud policy "
        b"for order 123\n"
        b"2026-10-11 09:01:00 ERROR Payment refused by fraud policy "
        b"for order 456\n")
    cause, artifact = _cause_for(
        data, "Payment refused by fraud policy for order <id>")
    assert cause == dd.ABSTENTION
    assert artifact["brief"]["lead"]["cause"] == dd.ABSTENTION


def test_adversarial_flat_timeline_and_clean_log():
    from app.service import analyze_upload
    flat = analyze_upload(
        "flat.log",
        b"2026-10-11 09:00:00 ERROR DatabaseError: connection to "
        b"db-01 refused\n"
        b"2026-10-11 09:00:00 WARN Connection pool exhausted\n")
    brief = dd.build_deep_dive(flat)["brief"]
    assert brief["sequence"] is not None
    assert len({e["first_seen"] for e in brief["sequence"]["entries"]}) == 1
    # Clean/quiet log: eligibility rejects before any brief exists
    # (regression gate — passes on both trees), and the pure helper
    # fabricates nothing for an empty group list.
    clean = analyze_upload(
        "clean.log",
        b"2026-10-11 09:00:00 INFO all good\n"
        b"2026-10-11 09:01:00 INFO still good\n")
    with pytest.raises(dd.InsufficientEvidence):
        dd.build_deep_dive(clean)
    empty = dd._build_brief(clean, [], {}, started=time.monotonic(),
                            clock=time.monotonic,
                            deadline_seconds=dd.GENERATION_DEADLINE_SECONDS)
    assert empty["lead"] is None and empty["sequence"] is None
    assert empty["priority_checks"] == []


def test_severity_only_group_no_excerpts_no_timestamps_checks():
    # A1/P2-4 fixture: eligible severity-only group, no excerpts, no
    # timestamps — motivation is non-temporal, nothing interpolates
    # a missing timestamp.
    payload = _synthetic_payload([
        {"template": "DatabaseError: connection to db-01 refused",
         "count": 4, "level": "ERROR"},
    ])
    brief = dd.build_deep_dive(payload)["brief"]
    assert brief["priority_checks"], "the rule check still renders"
    for check in brief["priority_checks"]:
        assert check["motivation"] and check["support"] and check["weaken"]
        assert "None" not in check["motivation"]
        assert "None" not in check["support"]
        assert "None" not in check["weaken"]
        assert "sample" in check["support"]  # bounded-sample caveat
    assert brief["priority_checks"][0]["motivation"].startswith("Recorded 4")


# --- 5. privacy ------------------------------------------------------------------

def test_planted_secret_redacted_across_brief_appendix_pdf_json():
    from app.service import analyze_upload
    from app.pdf_export import generate_deep_dive_pdf
    data = analyze_upload(
        "secret.log",
        b"2026-10-11 09:00:00 ERROR order failed: payment upstream "
        b"rejected api_key=plantedsecret123456789\n"
        b"2026-10-11 09:01:00 ERROR order failed: payment upstream "
        b"rejected api_key=plantedsecret123456789\n")
    artifact = dd.build_deep_dive(data)
    projection = dd.public_projection(artifact)
    surfaces = {
        "json": json.dumps(projection),
        "brief": json.dumps(projection["brief"]),
        "pdf": _pdf_text(generate_deep_dive_pdf(
            json.dumps(artifact), "secret.log")),
        "txt": "\n".join(dd.projection_text_lines(projection)),
    }
    for name, surface in surfaces.items():
        assert "plantedsecret123456789" not in surface, name
    assert "[REDACTED]" in surfaces["brief"]
    assert "[REDACTED]" in surfaces["pdf"]


def test_brief_excerpts_are_subset_of_appendix_excerpts():
    artifact = _sample_artifact()
    projection = dd.public_projection(artifact)
    lead_template = projection["brief"]["lead"]["template"]
    appendix = next(g for g in projection["groups"]
                    if g["template"] == lead_template)
    appendix_texts = {e["text"] for e in appendix["excerpts"]}
    brief_texts = {e["text"] for e in projection["brief"]["lead"]["excerpts"]}
    assert brief_texts and brief_texts <= appendix_texts
    assert len(projection["brief"]["lead"]["excerpts"]) <= 2


# --- 6. check structure ------------------------------------------------------------

def test_check_caps_and_duplicate_collapse_on_sample():
    brief = _sample_artifact()["brief"]
    checks = brief["priority_checks"]
    lead_checks = [c for c in checks
                   if c["template"] == brief["lead"]["template"]]
    assert 1 <= len(lead_checks) <= 3
    from collections import Counter
    per_finding = Counter(c["template"] for c in checks)
    assert all(n <= 3 for n in per_finding.values())
    non_lead = [t for t in per_finding if t != brief["lead"]["template"]]
    assert len(non_lead) <= 2
    assert all(per_finding[t] <= 2 for t in non_lead)
    texts = [" ".join(c["text"].split()).lower() for c in checks]
    assert len(texts) == len(set(texts)), "duplicates must collapse"
    for check in checks:
        assert check["motivation"] and check["support"] and check["weaken"]


def test_check_b_shows_only_shared_service_intersection():
    payload = _synthetic_payload([
        {"template": "Connection pool exhausted", "count": 2,
         "level": "WARN", "services": ["api", "db"],
         "first_seen": "2026-01-01T10:00:00.000Z",
         "excerpts": [_excerpt("pool exhausted in api and db")]},
        {"template": "DatabaseError: connection to db-01 refused",
         "count": 1, "level": "ERROR", "services": ["db", "cache"],
         "first_seen": "2026-01-01T11:00:00.000Z",
         "excerpts": [_excerpt("refused", "2026-01-01T11:00:00.000Z", 2)]},
    ])
    brief = dd.build_deep_dive(payload)["brief"]
    b_checks = [c for c in brief["priority_checks"]
                if "other messages recorded for service" in c["text"]]
    assert len(b_checks) == 1
    assert "service(s) db " in b_checks[0]["text"] or \
        "service(s) db in" in b_checks[0]["text"]
    assert "api" not in b_checks[0]["text"]
    assert "cache" not in b_checks[0]["text"]
    assert "2026-01-01T10:00:00.000Z" in b_checks[0]["text"]


def test_check_c_compares_full_timestamp_to_the_minute():
    base = [
        {"template": "Connection pool exhausted", "count": 2,
         "level": "WARN", "services": [],
         "first_seen": "2026-01-01T10:00:10.000Z",
         "excerpts": [_excerpt("pool exhausted")]},
    ]
    other_day = base + [{
        "template": "DatabaseError: connection to db-01 refused",
        "count": 1, "level": "ERROR", "services": [],
        "first_seen": "2026-01-02T10:00:40.000Z",  # same clock minute, next day
        "excerpts": [_excerpt("refused", "2026-01-02T10:00:40.000Z", 2)]}]
    brief = dd.build_deep_dive(_synthetic_payload(other_day))["brief"]
    assert not any("first recorded at" in c["text"] and "alongside" in c["text"]
                   for c in brief["priority_checks"])
    same_minute = base + [{
        "template": "DatabaseError: connection to db-01 refused",
        "count": 1, "level": "ERROR", "services": [],
        "first_seen": "2026-01-01T10:00:40.000Z",
        "excerpts": [_excerpt("refused", "2026-01-01T10:00:40.000Z", 2)]}]
    brief2 = dd.build_deep_dive(_synthetic_payload(same_minute))["brief"]
    c_checks = [c for c in brief2["priority_checks"] if "alongside" in c["text"]]
    assert len(c_checks) == 1 and "2026-01-01T10:00" in c_checks[0]["text"]


# --- 7. legacy artifacts -----------------------------------------------------------

def _legacy_artifact():
    artifact = _sample_artifact()
    legacy = copy.deepcopy(artifact)
    legacy.pop("brief", None)
    legacy["generator_version"] = "106-stage2-v1"
    return legacy


def test_legacy_artifact_renders_cleanly_everywhere():
    from app.pdf_export import generate_deep_dive_pdf
    legacy = _legacy_artifact()
    assert dd.validate_artifact(legacy)["schema_version"] == 1
    projection = dd.public_projection(legacy)
    assert projection["brief"] is None
    assert "Investigation Brief" not in "\n".join(
        dd.projection_text_lines(projection))
    pdf_text = _pdf_text(generate_deep_dive_pdf(
        json.dumps(legacy), SAMPLE_FILENAME))
    assert "Investigation Brief" not in pdf_text
    assert "connection pool exhausted" in pdf_text  # appendix still renders


# --- performance / deadline (A1/P2-8) ----------------------------------------------

def test_brief_deadline_clock_failure_is_clean():
    payload = _sample_payload()
    calls = {"n": 0}

    def fake_clock():
        # Sample build makes ~20 clock calls in total: started(1) +
        # 12 group-loop checks + pre-brief check + the brief's own
        # deadline checks. Tripping after call 16 lands the failure
        # INSIDE brief assembly (A1/P2-8), after groups are built.
        calls["n"] += 1
        return 0.0 if calls["n"] <= 16 else 1000.0

    with pytest.raises(dd.AnalysisError):
        dd.build_deep_dive(payload, clock=fake_clock)


def test_max_fixture_timing_and_storage_delta():
    specs = [{
        "template": f"Distinct failure variant {i} happened",
        "count": 1, "level": "ERROR", "services": ["db"],
        "first_seen": "2026-01-01T10:00:00.000Z",
    } for i in range(dd.MAX_GROUPS)]
    payload = _synthetic_payload(specs)
    started = time.monotonic()
    artifact = dd.build_deep_dive(payload)
    elapsed = time.monotonic() - started
    assert elapsed < dd.GENERATION_DEADLINE_SECONDS
    with_brief = len(json.dumps(artifact).encode())
    without = copy.deepcopy(artifact)
    without.pop("brief")
    without_bytes = len(json.dumps(without).encode())
    delta = (with_brief - without_bytes) / without_bytes
    assert delta <= 0.05, f"max-fixture brief delta {delta:.2%}"


# --- route-level helpers -------------------------------------------------------------

def _generate(auth_env, rid, csrf):
    return auth_env.client.post(
        f"/reports/{rid}/deep-dive", data={"csrf_token": csrf})


def _custom_result(auth_env, user_id, payload, *, report_type="analysis"):
    from app import models
    manifest = json.dumps(payload, default=str)
    now = datetime.now(timezone.utc)
    db = auth_env.sessions()
    try:
        result = models.Result(
            user_id=user_id, type=report_type,
            free_request_id=f"test-{uuid.uuid4().hex}",
            storage_manifest=manifest,
            integrity_digest=hashlib.sha256(manifest.encode()).hexdigest(),
            byte_count=len(manifest.encode()),
            ready_at=now, expires_at=now + timedelta(days=7))
        db.add(result)
        db.commit()
        return result.id
    finally:
        db.close()


def _eligible_payload():
    from app.service import analyze_upload
    data = analyze_upload(
        "eligible.log",
        b"2024-01-01 10:00:00 ERROR DatabaseError: connection to "
        b"db-01 refused\n"
        b"2024-01-01 10:00:01 ERROR DatabaseError: connection to "
        b"db-01 refused\n"
        b"2024-01-01 10:00:02 WARN Connection pool exhausted\n")
    assert "error" not in data, data
    return data


def _rewrite_artifact(auth_env, artifact_id, mutate):
    from app import models
    db = auth_env.sessions()
    try:
        row = db.get(models.Result, uuid.UUID(str(artifact_id)))
        manifest = json.loads(row.storage_manifest)
        mutate(manifest)
        blob = json.dumps(manifest, default=str)
        row.storage_manifest = blob
        row.integrity_digest = hashlib.sha256(blob.encode()).hexdigest()
        row.byte_count = len(blob.encode())
        db.commit()
    finally:
        db.close()


def _artifact_manifest(auth_env, artifact_id):
    from app import models
    db = auth_env.sessions()
    try:
        row = db.get(models.Result, uuid.UUID(str(artifact_id)))
        return json.loads(row.storage_manifest)
    finally:
        db.close()


# --- 8 / cross-feature route matrix --------------------------------------------------

def test_route_paid_html_contains_brief_free_page_does_not(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    free_page = auth_env.client.get(f"/reports/{rid}")
    assert free_page.status_code == 200
    assert "Investigation Brief" not in free_page.text
    assert dd.BRIEF_NOT_ESTABLISHED not in free_page.text
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200, gen.text[:300]
    page = auth_env.client.get(f"/reports/{gen.json()['analysis_result_id']}")
    assert page.status_code == 200
    assert "Investigation Brief" in page.text
    assert dd.BRIEF_NOT_ESTABLISHED in page.text
    assert "evidence_refs" not in page.text


def test_route_json_export_has_brief_csv_has_none(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    analysis_id = gen.json()["analysis_result_id"]
    json_r = auth_env.client.post(
        f"/reports/{analysis_id}/exports/json", data={"csrf_token": csrf})
    assert json_r.status_code == 200
    body = json.loads(json_r.content)
    assert body["brief"]["lead"] is not None
    assert body["brief"]["sequence"]["caption"] == dd.BRIEF_SEQUENCE_CAPTION
    assert "evidence_refs" not in json_r.content.decode()
    csv_r = auth_env.client.post(
        f"/reports/{analysis_id}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200
    assert b"Investigation Brief" not in csv_r.content
    assert csv_r.content.startswith(
        b"template,level,count,services,first_seen,last_seen")


def test_route_version_bump_old_view_free_then_confirm_new_purchase(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200
    old_id = gen.json()["analysis_result_id"]

    def _make_old(manifest):
        manifest.pop("brief", None)
        manifest["generator_version"] = "106-stage2-v1"
    _rewrite_artifact(auth_env, old_id, _make_old)
    # A genuine pre-#162 completion also carries the OLD canonical
    # identity: its operation's request_hash was computed with the
    # old GENERATOR_VERSION, so it cannot match the current hash.
    from app import models
    db = auth_env.sessions()
    try:
        for op in db.query(models.Operation).filter(
                models.Operation.type == "deep_dive").all():
            if str(op.result_id) == old_id:
                op.request_hash = "0" * 64
        db.commit()
    finally:
        db.close()

    before = _balance(auth_env, user_id)
    view = auth_env.client.get(f"/reports/{old_id}")
    assert view.status_code == 200  # old view: free, no brief, no charge
    assert "Investigation Brief" not in view.text
    assert _balance(auth_env, user_id) == before

    # Source page: version-aware discovery offers the popup again,
    # stating the new purchase (A1/P2-6 UX disposition).
    source_page = auth_env.client.get(f"/reports/{rid}")
    assert source_page.status_code == 200
    assert "Generating a new Analysis Report is a new" in source_page.text
    assert 'id="analysis-btn"' in source_page.text

    confirm = _generate(auth_env, rid, csrf)
    assert confirm.status_code == 200, confirm.text[:300]
    assert confirm.json()["analysis_result_id"] != old_id
    assert _balance(auth_env, user_id) == before - 3  # exactly one new debit
    new_manifest = _artifact_manifest(
        auth_env, confirm.json()["analysis_result_id"])
    assert new_manifest["brief"]["lead"] is not None
    assert new_manifest["generator_version"] == "162-brief-v1"

    # Duplicate current Confirm replays: one artifact, no second debit.
    again = _generate(auth_env, rid, csrf)
    assert again.status_code == 200
    assert again.json()["analysis_result_id"] == \
        confirm.json()["analysis_result_id"]
    assert again.json()["replayed"] is True
    assert _balance(auth_env, user_id) == before - 3
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_route_brief_failure_reverses_and_prior_artifact_untouched(
        auth_env, monkeypatch):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    assert gen.status_code == 200
    prior_id = gen.json()["analysis_result_id"]
    prior_manifest = _artifact_manifest(auth_env, prior_id)

    rid2 = _custom_result(auth_env, user_id, _eligible_payload())
    csrf2 = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    monkeypatch.setattr(
        dd, "_build_brief",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("brief boom")))
    r = _generate(auth_env, rid2, csrf2)
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == before  # full reversal
    assert _artifact_manifest(auth_env, prior_id) == prior_manifest
    view = auth_env.client.get(f"/reports/{prior_id}")
    assert view.status_code == 200 and "Investigation Brief" in view.text
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_route_post_brief_persistence_failure_reverses(auth_env, monkeypatch):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    real_store = C.store_result

    def _boom(db, user, op_id, data, **kwargs):
        if kwargs.get("result_type") == "deep_dive":
            raise RuntimeError("store boom")
        return real_store(db, user, op_id, data, **kwargs)
    monkeypatch.setattr(C, "store_result", _boom)
    r = _generate(auth_env, rid, csrf)
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == before
    ops = _ops(auth_env, user_id, "deep_dive")
    assert len(ops) == 1 and ops[0].status == "failed"
    assert ops[0].result_id is None  # no partial artifact
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_route_old_artifact_unlock_and_new_artifact_unlock(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    old_id = gen.json()["analysis_result_id"]
    _rewrite_artifact(auth_env, old_id, lambda m: m.pop("brief", None))
    before = _balance(auth_env, user_id)
    pdf = auth_env.client.post(
        f"/reports/{old_id}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before - 2  # its own unlock
    assert "Investigation Brief" not in _pdf_text(pdf.content)
    csv_r = auth_env.client.post(
        f"/reports/{old_id}/exports/csv", data={"csrf_token": csrf})
    assert csv_r.status_code == 200
    assert _balance(auth_env, user_id) == before - 2  # replay free

    # New brief-bearing artifact: its own unlock, PDF carries brief.
    rid2 = _custom_result(auth_env, user_id, _eligible_payload())
    csrf2 = _session_csrf(auth_env)
    gen2 = _generate(auth_env, rid2, csrf2)
    assert gen2.status_code == 200, gen2.text[:300]
    new_id = gen2.json()["analysis_result_id"]
    before2 = _balance(auth_env, user_id)
    pdf2 = auth_env.client.post(
        f"/reports/{new_id}/pdf", data={"csrf_token": csrf2})
    assert pdf2.status_code == 200
    assert _balance(auth_env, user_id) == before2 - 2
    assert "Investigation Brief" in _pdf_text(pdf2.content)
    pdf3 = auth_env.client.post(
        f"/reports/{new_id}/pdf", data={"csrf_token": csrf2})
    assert pdf3.status_code == 200
    assert _balance(auth_env, user_id) == before2 - 2  # unlocked replay free


def test_route_failed_first_export_charges_zero_unlock_intact(
        auth_env, monkeypatch):
    import app.pdf_export as pdf_export
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    analysis_id = gen.json()["analysis_result_id"]
    before = _balance(auth_env, user_id)
    real_pdf = pdf_export.generate_deep_dive_pdf
    monkeypatch.setattr(
        pdf_export, "generate_deep_dive_pdf",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("pdf boom")))
    r = auth_env.client.post(
        f"/reports/{analysis_id}/pdf", data={"csrf_token": csrf})
    assert r.status_code == 500
    assert _balance(auth_env, user_id) == before
    monkeypatch.setattr(pdf_export, "generate_deep_dive_pdf", real_pdf)
    ok = auth_env.client.post(
        f"/reports/{analysis_id}/pdf", data={"csrf_token": csrf})
    assert ok.status_code == 200 and ok.content[:4] == b"%PDF"
    assert _balance(auth_env, user_id) == before - 2  # charged once, on success


def test_route_deep_dive_share_and_extend_stay_unsupported(auth_env):
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    analysis_id = gen.json()["analysis_result_id"]
    before = _balance(auth_env, user_id)
    share = auth_env.client.post(
        f"/reports/{analysis_id}/share",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert share.status_code in (404, 422)
    extend = auth_env.client.post(
        f"/reports/{analysis_id}/retention",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert extend.status_code in (404, 422)
    assert _balance(auth_env, user_id) == before
    # Sharing the STANDARD SOURCE does not share its Analysis Report.
    src_share = auth_env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert src_share.status_code == 200
    share2 = auth_env.client.post(
        f"/reports/{analysis_id}/share",
        data={"csrf_token": csrf, "idempotency_key": uuid.uuid4().hex})
    assert share2.status_code in (404, 422)
    assert _balance(auth_env, user_id) == before


def test_route_source_vs_derived_expiry_are_separate(auth_env):
    from app import models
    _, user_id, rid, csrf = _setup(auth_env)
    gen = _generate(auth_env, rid, csrf)
    analysis_id = gen.json()["analysis_result_id"]
    db = auth_env.sessions()
    try:
        row = db.get(models.Result, uuid.UUID(analysis_id))
        row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    finally:
        db.close()
    derived = auth_env.client.get(f"/reports/{analysis_id}")
    assert derived.status_code == 410  # derived expiry governs itself
    source = auth_env.client.get(f"/reports/{rid}")
    assert source.status_code == 200  # source unaffected
    # Expired SOURCE rejects generation with 410, no charge.
    rid2 = _custom_result(auth_env, user_id, _eligible_payload())
    db = auth_env.sessions()
    try:
        row = db.get(models.Result, rid2)
        row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    finally:
        db.close()
    csrf2 = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    r = _generate(auth_env, rid2, csrf2)
    assert r.status_code == 410
    assert _balance(auth_env, user_id) == before
