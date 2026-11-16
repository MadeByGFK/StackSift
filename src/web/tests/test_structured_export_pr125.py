"""PR #125 remediation regression tests (issue #105, Codex findings 1-5).

Each test is designed to FAIL on the pre-fix tree (head 5aec0b59) and
PASS on the fixed tree; see the builder report for teeth evidence.
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app import credits as C
from app import structured_export as se
from test_structured_export_e2e import (
    _artifacts,
    _balance,
    _custom_result,
    _grant,
    _ops,
    _sample_payload,
    _seed_completed_structured_artifact,
    _session_csrf,
    _setup,
)
from test_phase2b_reports_pdf import _create_result, _login, _signup_and_verify


# ---------------------------------------------------------------------------
# Finding 3: validate_exportable separates validation from generation
# ---------------------------------------------------------------------------

def test_validate_exportable_does_not_call_generate_export(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("generate_export must not be called by validation")
    monkeypatch.setattr(se, "generate_export", boom)
    # Valid payload validates without generation.
    se.validate_exportable(_sample_payload(), "csv")
    se.validate_exportable(_sample_payload(), "json")
    # Unserializable / contradicted payload still fails validation.
    bad = _sample_payload()
    bad["sorted_issues"][0][1]["count"] = 999
    with pytest.raises(se.StructuredExportError):
        se.validate_exportable(bad, "csv")
    with pytest.raises(se.UnsupportedReportKind):
        se.validate_exportable(_sample_payload(report_kind="comparison"), "csv")


def test_402_path_does_not_call_generate_export(auth_env, monkeypatch):
    # PREMISE CHANGED (issue #164 Phase C): there is no 402 path —
    # a spend-restricted user (positive balance, zero eligible)
    # exports FREE: the generator runs exactly once (the free
    # generation; validation does not call it), and no operation or
    # artifact is left behind.
    _, user_id, rid, csrf = _setup(auth_env)
    from app import models
    db = auth_env.sessions()
    try:
        db.add(models.Restriction(user_id=user_id, action="spend",
                                  cause_type="test", cause_id="t", reason="test"))
        db.commit()
    finally:
        db.close()
    calls = {"n": 0}
    real = se.generate_export
    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)
    monkeypatch.setattr(se, "generate_export", counting)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    assert calls["n"] == 1
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []


def test_completed_replay_does_not_call_generate_export(auth_env, monkeypatch):
    # PREMISE PRESERVED, setup re-based (Phase C): replay of a
    # SEEDED completed operation serves its stored artifact without
    # running the generator (a free export stores nothing, so the
    # completed attempt is seeded directly).
    _, user_id, rid, csrf = _setup(auth_env)
    _op_id, _artifact_id, seeded_bytes = _seed_completed_structured_artifact(
        auth_env, user_id, rid, fmt="csv")
    def boom(*a, **k):
        raise se.StructuredExportError("generator must not run on replay")
    monkeypatch.setattr(se, "generate_export", boom)
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 200, r2.text[:300]
    assert r2.content == seeded_bytes
    assert len(_ops(auth_env, user_id)) == 1


def test_unserializable_422_before_reservation_and_no_generation(auth_env, monkeypatch):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    payload = _sample_payload()
    payload["sorted_issues"][0][1]["count"] = 999
    rid = _custom_result(auth_env, user_id, payload)
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    calls = {"n": 0}
    real = se.generate_export
    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)
    monkeypatch.setattr(se, "generate_export", counting)
    before = _balance(auth_env, user_id)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 422, r.text[:300]
    assert calls["n"] == 0
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []


# ---------------------------------------------------------------------------
# Finding 4: real comparison reports (type="comparison") -> 422, not 404
# ---------------------------------------------------------------------------

def test_comparison_type_source_returns_422_before_charge(auth_env):
    email, user_id = _signup_and_verify(auth_env)
    _grant(auth_env, user_id, 10)
    rid = _custom_result(
        auth_env, user_id, _sample_payload(report_kind="comparison"),
        report_type="comparison",
    )
    _login(auth_env, email)
    csrf = _session_csrf(auth_env)
    before = _balance(auth_env, user_id)
    for fmt in ("csv", "json"):
        r = auth_env.client.post(f"/reports/{rid}/exports/{fmt}", data={"csrf_token": csrf})
        assert r.status_code == 422, (fmt, r.status_code, r.text[:200])
        assert "not yet supported" in r.json()["error"]
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == [] and _artifacts(auth_env, user_id) == []


# ---------------------------------------------------------------------------
# Finding 2: release failure_code bounded to String(50) with a stable code
# ---------------------------------------------------------------------------

def test_generation_failure_stores_bounded_stable_failure_code(auth_env, monkeypatch):
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    real = se.payload_to_csv
    calls = {"n": 0}
    long_msg = "boom " + ("x" * 300)
    def flaky(payload):
        calls["n"] += 1
        if calls["n"] == 2:  # validation (1) passes, generation (2) fails
            raise RuntimeError(long_msg)
        return real(payload)
    monkeypatch.setattr(se, "payload_to_csv", flaky)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 500, r.text[:300]
    # PREMISE CHANGED (issue #164 Phase C): a free generation admits
    # no operation, so there is nothing to release and nothing is
    # stored — no failed op, no failure_code row, balance untouched.
    # (The bounded-code rule still governs the legacy admission path
    # wherever it remains reachable; it is unreachable here.)
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == []
    assert _artifacts(auth_env, user_id) == []
    with auth_env.sessions() as db:
        assert C.verify_account_invariants(db, user_id) == []


def test_storage_failure_stores_bounded_stable_failure_code(auth_env, monkeypatch):
    # PREMISE CHANGED (issue #164 Phase C): a free export never calls
    # the store, so a storage failure cannot occur on this path —
    # the export succeeds and stores nothing (no failed op, no
    # failure_code row, balance untouched).
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    long_msg = "store boom " + ("y" * 300)
    monkeypatch.setattr(
        C, "store_structured_export_result",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError(long_msg)))
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    assert _balance(auth_env, user_id) == before
    assert _ops(auth_env, user_id) == []
    assert _artifacts(auth_env, user_id) == []


# ---------------------------------------------------------------------------
# Finding 5: artifact provenance binding
# ---------------------------------------------------------------------------

def _manifest(data=b"template,level\r\n", **overrides):
    manifest = {
        "artifact_kind": "structured_export", "schema_version": 1,
        "source_result_id": "src-1", "source_integrity_digest": "a" * 64,
        "format": "csv",
        "content_base64": base64.b64encode(data).decode(),
        "content_byte_count": len(data),
        "content_digest": hashlib.sha256(data).hexdigest(),
    }
    manifest.update(overrides)
    return manifest


def test_decode_artifact_requires_provenance():
    out, _ = se.decode_artifact(
        _manifest(), expected_source_integrity_digest="a" * 64)
    assert out == b"template,level\r\n"
    for mutated in (
        {k: v for k, v in _manifest().items() if k != "source_integrity_digest"},
        {k: v for k, v in _manifest().items() if k != "source_result_id"},
        _manifest(source_integrity_digest=""),
        _manifest(source_integrity_digest="   "),
        _manifest(source_result_id=""),
        _manifest(source_result_id=None),
    ):
        with pytest.raises(se.StructuredExportError):
            se.decode_artifact(mutated)
    with pytest.raises(se.StructuredExportError):
        se.decode_artifact(_manifest(), expected_source_integrity_digest="b" * 64)


def _reseal(auth_env, result_id, mutate):
    from app import models
    db = auth_env.sessions()
    try:
        art = db.get(models.Result, result_id)
        manifest = json.loads(art.storage_manifest)
        mutate(manifest)
        raw = json.dumps(manifest)
        art.storage_manifest = raw
        art.integrity_digest = hashlib.sha256(raw.encode()).hexdigest()
        art.byte_count = len(raw.encode())
        db.commit()
    finally:
        db.close()


def test_get_download_rejects_provenance_mismatch(auth_env):
    # PREMISE PRESERVED, setup re-based (Phase C): the stored
    # artifact is seeded directly (free exports store none).
    _, user_id, rid, csrf = _setup(auth_env)
    _op_id, artifact_id, _seeded = _seed_completed_structured_artifact(
        auth_env, user_id, rid, fmt="csv")
    url = f"/exports/{artifact_id}"
    export_id = artifact_id
    assert auth_env.client.get(url).status_code == 200
    # Tamper only the provenance digest, re-sealing the envelope so
    # result_payload integrity still passes: GET must fail closed
    # because the recomputed hash no longer matches the Operation.
    _reseal(auth_env, export_id,
            lambda m: m.update(source_integrity_digest="f" * 64))
    assert auth_env.client.get(url).status_code == 410


def test_post_replay_rejects_provenance_mismatch(auth_env):
    # PREMISE PRESERVED, setup re-based (Phase C): seeded artifact.
    _, user_id, rid, csrf = _setup(auth_env)
    _op_id, export_id, _seeded = _seed_completed_structured_artifact(
        auth_env, user_id, rid, fmt="csv")
    _reseal(auth_env, export_id,
            lambda m: m.update(source_integrity_digest="f" * 64))
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 410, r2.text[:300]


# ---------------------------------------------------------------------------
# Finding 1: retry-chain discovery serialized under the global:paid lock
# ---------------------------------------------------------------------------

def test_lock_global_paid_scope_helper(auth_env):
    db = auth_env.sessions()
    try:
        scope = C.lock_global_paid_scope(db)
        assert scope.scope_key == "global:paid"
        db.rollback()
    finally:
        db.close()


def test_route_locks_chain_before_admission_and_on_replay(auth_env, monkeypatch):
    """Sequential simulation of the interleaving: the lock must be
    taken before admission (new export) and also before discovery on
    the replay path. SQLite FOR UPDATE is a no-op, so this verifies
    lock acquisition/order, not true PG blocking (see report)."""
    order = []
    orig_lock = getattr(C, "lock_global_paid_scope", None)
    def lock_spy(db, *a, **k):
        order.append("lock")
        if orig_lock is not None:
            return orig_lock(db, *a, **k)
    monkeypatch.setattr(C, "lock_global_paid_scope", lock_spy, raising=False)
    orig_admit = C.admit_paid_operation
    def admit_spy(db, *a, **k):
        order.append("admit")
        return orig_admit(db, *a, **k)
    monkeypatch.setattr(C, "admit_paid_operation", admit_spy)
    _, user_id, rid, csrf = _setup(auth_env)
    order.clear()
    r1 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r1.status_code == 200, r1.text[:300]
    # PREMISE CHANGED (issue #164 Phase C): the global:paid lock is
    # still taken before discovery, but a free export is NEVER
    # admitted — no admission on the first generation either.
    assert order == ["lock"], order
    # Second POST: lock is taken (before discovery) and, again, no
    # admission occurs; the bytes are regenerated free, identical.
    order.clear()
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 200 and r2.content == r1.content
    assert order == ["lock"], order
    assert len(_ops(auth_env, user_id)) == 0


def test_retry_chain_after_failure_charges_once(auth_env, monkeypatch):
    """After a failed attempt, the first retry completes and a second
    retry discovers it under the lock and replays free (one charge).

    PREMISE CHANGED (issue #164 Phase C): the charge is ZERO — a
    failed free generation stores no operation, the retry generates
    free, and a second retry serves identical bytes, still with no
    operation ever created."""
    _, user_id, rid, csrf = _setup(auth_env)
    before = _balance(auth_env, user_id)
    real = se.payload_to_csv
    calls = {"n": 0}
    def flaky(payload):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(payload)
    monkeypatch.setattr(se, "payload_to_csv", flaky)
    r = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r.status_code == 500
    monkeypatch.setattr(se, "payload_to_csv", real)
    r2 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r2.status_code == 200, r2.text[:300]
    r3 = auth_env.client.post(f"/reports/{rid}/exports/csv", data={"csrf_token": csrf})
    assert r3.status_code == 200 and r3.content == r2.content
    assert _balance(auth_env, user_id) == before
    completed = [o for o in _ops(auth_env, user_id) if o.status == "completed"]
    assert completed == []
    assert _ops(auth_env, user_id) == []
