"""Issue #135 / PR #138 remediation round 1: five Codex P2 findings.

F1: share-popup state was report-wide (``share_active``), not
    per-format — after creating a TXT link, other formats hid Create
    and showed a Rotate that 409s. State is now per format in both
    popups (report page + My Reports).
F2: Settings -> Report Access filtered out active pre-#135 legacy
    rows (raw_token NULL / share_format NULL, read as txt) even
    though their links still serve.
F3: Settings revoke locked the sharing row BEFORE the share rate
    bucket — the inverse of every other share handler (deadlock on
    PostgreSQL, aborted revoke leaves the token live).
F4: action_request_hash unconditionally added ``share_format``,
    breaking replay of pre-deploy retention purchases (and legacy
    share actions) recorded under the pre-#135 hash.
F5: migration 0014 downgrade recreated the unique index on
    result_id while multi-format rows exist (covered in
    test_report_access_migrations.py).

TEETH: every test in this file fails on the pre-fix tree (remote
head f66bff35) and passes on the fixed tree — verified by running
this file against a pristine checkout of f66bff35.
"""

import ast
import json
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2b_paid_e2e import paid_env, _signup_verify_login, _http_balance  # noqa: F401
from test_report_sharing import _anon_client, _create_share, _make_report, _token_from
from test_structured_export_e2e import _grant

from app import auth, credits as C, main, models as M
from app import report_access as RA


def _legacy_hash(source_id, integrity_digest, action_kind):
    """The pre-#135 hash, computed independently of the code under test."""
    payload = {
        "action_kind": action_kind,
        "source_result_id": str(source_id),
        "source_integrity_digest": integrity_digest,
        "unit_days": C.RETENTION_EXTENSION_DAYS
        if action_kind == "retention_extension" else None,
        "version": 1,
    }
    return C.hash_input(json.dumps(
        payload, sort_keys=True, separators=(",", ":")).encode())


def _source_row(env, rid):
    with env.sessions() as db:
        result = db.get(M.Result, rid)
        return result.integrity_digest, result.expires_at


def _setup_unlocked_csv_only(env):
    _, uid, csrf = _signup_verify_login(env)
    _grant(env, uid, 10)
    rid = _make_report(env, uid)
    r = env.client.post(f"/reports/{rid}/exports/csv",
                        data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    resp = env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": "f1-csv-only",
              "format": "csv"})
    assert resp.status_code == 200, resp.text[:300]
    return uid, csrf, rid


# --- F1: per-format popup state ----------------------------------------------

def test_f1_report_page_initial_buttons_follow_txt_not_any_format(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked_csv_only(env)
    page = env.client.get(f"/reports/{rid}")
    assert page.status_code == 200
    text = page.text
    # Only CSV has a link; TXT (the default selected format) has
    # none, so Create must be VISIBLE for txt and Rotate/Revoke
    # hidden — the old report-wide share_active hid Create instead.
    assert 'id="share-create" style="display:none"' not in text
    assert 'id="share-rotate" style="display:none"' in text
    assert 'id="share-revoke" style="display:none"' in text
    # Per-format state is rendered and drives visibility on change.
    assert "shareActiveFormats" in text
    assert '"csv"' in text
    assert "shareFormatIsActive" in text
    assert "'change', refreshShareButtonsForSelectedFormat" in text \
        or '"change", refreshShareButtonsForSelectedFormat' in text \
        or "addEventListener('change', refreshShareButtonsForSelectedFormat)" in text


def test_f1_reports_page_rows_carry_per_format_state(paid_env):
    env = paid_env
    uid, csrf, rid = _setup_unlocked_csv_only(env)
    page = env.client.get("/reports")
    assert page.status_code == 200
    text = page.text
    assert 'data-formats="csv"' in text
    assert "activeFormatsFor" in text
    assert "addEventListener('change', refreshShareButtonsForSelectedFormat)" in text


# --- F2: legacy rows in Settings -> Report Access -----------------------------

def test_f2_legacy_row_is_listed_with_note_and_revoke_works(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    raw_token = auth.generate_token()
    with env.sessions() as db:
        row = M.ReportSharing(
            result_id=rid, owner_user_id=uid,
            token_hash=auth.hash_token(raw_token), generation=1,
            share_format=None, raw_token=None)
        db.add(row)
        db.commit()
        db.refresh(row)
        sharing_id = str(row.id)
        created = row.created_at.strftime("%Y-%m-%d %H:%M UTC")
    # The legacy link still serves.
    anon = _anon_client()
    assert anon.get(f"/s/{raw_token}").status_code == 200
    html = env.client.get("/settings").text
    assert "test.log" in html  # the report
    assert "TXT" in html  # NULL format reads as txt
    assert created in html
    # The URL cannot be redisplayed (token was never stored): an
    # explicit note replaces it — never the token, never "/s/None".
    assert "link not recoverable — revoke and create a new link" in html
    assert f"/s/{raw_token}" not in html
    assert "/s/None" not in html
    # Revoke from Settings stays fully functional for legacy rows.
    r = env.client.post(
        f"/settings/report-access/{sharing_id}/revoke",
        data={"csrf_token": csrf, "idempotency_key": "f2-legacy-revoke"})
    assert r.status_code == 200, r.text[:300]
    assert r.json() == {"status": "revoked"}
    assert anon.get(f"/s/{raw_token}").status_code == 404


# --- F3: lock order in Settings revoke -----------------------------------------

def test_f3_settings_revoke_locks_bucket_before_sharing_row():
    src = Path(main.__file__).read_text()
    tree = ast.parse(src)
    node = next(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == "settings_report_access_revoke")
    seg = ast.get_source_segment(src, node)
    lock_idx = seg.find("lock_share_rate_bucket")
    row_lock_idx = seg.find("with_for_update")
    replay_idx = seg.find("_share_action_replay")
    assert lock_idx != -1, "settings revoke: no share bucket lock"
    assert row_lock_idx != -1, "settings revoke: no sharing-row lock"
    assert lock_idx < row_lock_idx, (
        "settings revoke locks the sharing row BEFORE the rate "
        "bucket — the inverse of create/rotate/report-revoke")
    assert lock_idx < replay_idx


# --- F4: hash compatibility ------------------------------------------------------

def test_f4_retention_hash_is_byte_identical_to_pre135():
    source = SimpleNamespace(id=uuid.uuid4(), integrity_digest="0" * 64)
    expected = _legacy_hash(source.id, source.integrity_digest,
                            "retention_extension")
    assert RA.action_request_hash(source, "retention_extension") == expected
    # No share_format key for non-share actions, even if one is passed.
    assert RA.action_request_hash(
        source, "retention_extension", share_format="pdf") == expected


def test_f4_share_hash_binds_format_and_legacy_matches_only_txt():
    source = SimpleNamespace(id=uuid.uuid4(), integrity_digest="1" * 64)
    legacy = _legacy_hash(source.id, source.integrity_digest, "share_create")
    txt_hash = RA.action_request_hash(source, "share_create", share_format="txt")
    csv_hash = RA.action_request_hash(source, "share_create", share_format="csv")
    assert txt_hash != csv_hash
    assert txt_hash != legacy  # post-#135 canonical form binds the format
    matches = RA.action_hash_matches
    # A legacy (pre-#135) create record replays as txt — same semantics.
    assert matches(legacy, source, "share_create", txt_hash,
                   share_format="txt") is True
    # ...but never as a gated format.
    assert matches(legacy, source, "share_create", csv_hash,
                   share_format="csv") is False
    # Exact current hashes always match; unrelated hashes never do.
    assert matches(csv_hash, source, "share_create", csv_hash,
                   share_format="csv") is True
    assert matches("f" * 64, source, "share_create", txt_hash,
                   share_format="txt") is False


def test_f4_retention_replay_with_legacy_hash_returns_recorded_success(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    integrity, expires_at = _source_row(env, rid)
    new_expiry = expires_at + timedelta(
        days=C.RETENTION_EXTENSION_DAYS)
    with env.sessions() as db:
        db.add(M.ReportAction(
            owner_user_id=uid, result_id=rid,
            action_kind="retention_extension",
            idempotency_key="f4-legacy-retention",
            request_hash=_legacy_hash(rid, integrity, "retention_extension"),
            resulting_expiry=new_expiry))
        db.commit()
    balance_before = _http_balance(env)
    resp = env.client.post(
        f"/reports/{rid}/retention",
        data={"csrf_token": csrf, "idempotency_key": "f4-legacy-retention"})
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert body.get("status") == "extended"
    assert body.get("replayed") is True
    assert _http_balance(env) == balance_before  # replay charges nothing


def test_f4_share_create_replay_with_legacy_hash_is_already_shared(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    first = _create_share(env, rid, csrf, key="f4-create-orig")
    assert first.status_code == 200, first.text[:300]
    token = _token_from(first)
    integrity, _ = _source_row(env, rid)
    with env.sessions() as db:
        db.add(M.ReportAction(
            owner_user_id=uid, result_id=rid, action_kind="share_create",
            idempotency_key="f4-legacy-create",
            request_hash=_legacy_hash(rid, integrity, "share_create"),
            generation=1))
        db.commit()
    replay = env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": "f4-legacy-create",
              "format": "txt"})
    assert replay.status_code == 200, replay.text[:300]
    assert replay.json().get("status") == "already_shared"
    assert "share_url" not in replay.json()
    assert _anon_client().get(f"/s/{token}").status_code == 200
    # The same legacy key replayed for a gated format still conflicts.
    conflict = env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": "f4-legacy-create",
              "format": "csv"})
    assert conflict.status_code == 409, conflict.text[:300]


def test_f4_share_rotate_replay_with_legacy_hash_is_already_rotated(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    first = _create_share(env, rid, csrf, key="f4-rot-orig")
    assert first.status_code == 200, first.text[:300]
    token = _token_from(first)
    integrity, _ = _source_row(env, rid)
    with env.sessions() as db:
        db.add(M.ReportAction(
            owner_user_id=uid, result_id=rid, action_kind="share_rotate",
            idempotency_key="f4-legacy-rotate",
            request_hash=_legacy_hash(rid, integrity, "share_rotate"),
            generation=1))
        db.commit()
    replay = env.client.post(
        f"/reports/{rid}/share/rotate",
        data={"csrf_token": csrf, "idempotency_key": "f4-legacy-rotate",
              "format": "txt"})
    assert replay.status_code == 200, replay.text[:300]
    assert replay.json().get("status") == "already_rotated"
    assert "share_url" not in replay.json()
    # No second rotation happened.
    assert _anon_client().get(f"/s/{token}").status_code == 200
