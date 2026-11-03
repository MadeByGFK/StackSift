"""Issue #107 PR #128 round 2: Codex P2 remediations.

F1: already-shared create records a ReportAction, so its replay
    preserves the original outcome (no rate, no new link after revoke).
F2: share-action replay lookup is serialized under the rate-bucket
    lock acquired BEFORE the lookup.
F3: share-path log redaction preserves Uvicorn's 5-arg access record.
F4: shared page charts use a CSP nonce + generated rules, no inline
    style attributes.
"""

import ast
import inspect
import logging
import re
from pathlib import Path

import pytest
from test_account_migrations import migrated_engine  # noqa: F401
from test_phase2b_paid_e2e import paid_env, _signup_verify_login, _http_balance  # noqa: F401
from test_report_sharing import (
    _make_report, _create_share, _token_from, _anon_client,
)

from app import credits as C, main, models as M


# ---------------- F1 ----------------

def test_f1_already_shared_create_records_action_and_replay_after_revoke(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    first = _create_share(env, rid, csrf, key="f1-create-1")
    assert first.status_code == 200, first.text[:400]
    token = _token_from(first)
    # Second create (new key) on already-shared report: already_shared.
    second = _create_share(env, rid, csrf, key="f1-create-2")
    assert second.status_code == 200, second.text[:400]
    assert second.json().get("status") == "already_shared"
    assert "share_url" not in second.json()
    # The no-op create MUST have recorded a ReportAction for its key,
    # with the existing active sharing's generation (1).
    with env.sessions() as db:
        actions = db.query(M.ReportAction).filter(
            M.ReportAction.owner_user_id == uid,
            M.ReportAction.result_id == rid,
            M.ReportAction.action_kind == "share_create",
            M.ReportAction.idempotency_key == "f1-create-2").all()
        assert len(actions) == 1, "already-shared create recorded no action"
        assert actions[0].generation == 1
        bucket_before = db.query(M.RateBucket).filter(
            M.RateBucket.policy == "share:actions",
            M.RateBucket.owner == str(uid)).one()
        attempts_before = bucket_before.attempts
    # Revoke the link.
    rev = env.client.post(f"/reports/{rid}/share/revoke",
                          data={"csrf_token": csrf, "idempotency_key": "f1-rev"})
    assert rev.status_code == 200, rev.text[:400]
    anon = _anon_client()
    assert anon.get(f"/s/{token}").status_code == 404
    with env.sessions() as db:
        bucket_mid = db.query(M.RateBucket).filter(
            M.RateBucket.policy == "share:actions",
            M.RateBucket.owner == str(uid)).one()
        attempts_mid = bucket_mid.attempts
    # Replay the second create's key: must return its stored
    # already_shared outcome, NOT create a new active link, and NOT
    # consume additional rate (only the revoke consumed since before).
    replay = _create_share(env, rid, csrf, key="f1-create-2")
    assert replay.status_code == 200, replay.text[:400]
    assert replay.json().get("status") == "already_shared"
    assert "share_url" not in replay.json()
    with env.sessions() as db:
        row = db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).one()
        assert row.token_hash is None and row.revoked_at is not None, (
            "replay of already-shared create created a new active link")
        bucket_after = db.query(M.RateBucket).filter(
            M.RateBucket.policy == "share:actions",
            M.RateBucket.owner == str(uid)).one()
        assert bucket_after.attempts == attempts_mid, (
            "replay consumed rate")
    assert anon.get(f"/s/{token}").status_code == 404


# ---------------- F2 ----------------

def test_f2_lock_acquired_before_replay_lookup_in_all_share_handlers():
    """Lock-ordering contract: in create/rotate/revoke the bucket lock
    call must appear before the replay lookup in source order, and the
    replay path must not consume rate (pinned behaviourally by F1 and
    by the at-limit replay test in test_report_sharing.py)."""
    src = Path(main.__file__).read_text()
    tree = ast.parse(src)
    handlers = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in ("report_share_create", "report_share_rotate",
                                  "report_share_revoke"):
            handlers[node.name] = node
    assert len(handlers) == 3
    for name, node in handlers.items():
        seg = ast.get_source_segment(src, node)
        lock_idx = seg.find("lock_share_rate_bucket")
        replay_idx = seg.find("_share_action_replay")
        assert lock_idx != -1, f"{name}: no share bucket lock"
        assert replay_idx != -1, f"{name}: no replay lookup"
        assert lock_idx < replay_idx, (
            f"{name}: replay lookup precedes lock acquisition")


def test_f2_lock_helper_locks_current_share_bucket(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create_share(env, rid, csrf, key="f2-lock-create")
    assert resp.status_code == 200
    with env.sessions() as db:
        bucket = C.lock_share_rate_bucket(db, str(uid))
        assert bucket.policy == "share:actions"
        assert bucket.owner == str(uid)
        assert bucket.attempts == 1  # the create above; locking consumes nothing
        db.rollback()


# ---------------- F3 ----------------

def test_f3_uvicorn_access_record_redaction_preserves_formatting():
    from app.report_access import SharePathRedactionFilter
    from uvicorn.logging import AccessFormatter
    token = "b" * 64
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:50000", "GET", f"/s/{token}", "1.1", 200), None)
    SharePathRedactionFilter().filter(record)
    # Args structure preserved for AccessFormatter's 5-value unpack.
    assert isinstance(record.args, tuple) and len(record.args) == 5
    assert record.args[2] == "/s/[redacted]"
    formatter = AccessFormatter(
        fmt='%(client_addr)s - "%(request_line)s" %(status_code)s',
        use_colors=False)
    out = formatter.format(record)
    assert "/s/[redacted]" in out
    assert token not in out
    # Fallback branch (same test): a non-Uvicorn record with an
    # already-rendered message must still be redacted without
    # breaking standard formatting.
    token2 = "c" * 64
    plain = logging.LogRecord(
        "app.main", logging.INFO, __file__, 1,
        f"served /s/{token2} ok", (), None)
    SharePathRedactionFilter().filter(plain)
    assert token2 not in plain.getMessage()
    assert "[redacted]" in plain.getMessage()


# ---------------- F4 ----------------

def test_f4_shared_page_nonce_csp_and_no_inline_styles(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    # Fixture report with deterministic chart data: the SAMPLE_LOG
    # payload has timeline/severity/service data (existing tests rely
    # on it rendering). Create + share it.
    rid = _make_report(env, uid)
    resp = _create_share(env, rid, csrf, key="f4-create")
    assert resp.status_code == 200, resp.text[:400]
    token = _token_from(resp)
    r = _anon_client().get(f"/s/{token}")
    assert r.status_code == 200, r.text[:300]
    csp = r.headers.get("content-security-policy", "")
    m = re.search(r"'nonce-([^']+)'", csp)
    assert m, f"CSP carries no nonce: {csp}"
    nonce = m.group(1)
    assert "unsafe-inline" not in csp
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    # The nonced style block exists and matches the header nonce.
    sm = re.search(r'<style nonce="([^"]+)">(.*?)</style>', r.text, re.S)
    assert sm, "no nonced <style> block in shared page"
    assert sm.group(1) == nonce
    css = sm.group(2)
    # No inline style attributes anywhere on the shared page.
    assert "style=" not in r.text.replace(
        f'<style nonce="{nonce}">', "<style>"), r.text[:2000]
    # Generated rules carry percentage dimensions for the charts.
    assert re.search(r"\.ss-dyn-[a-z0-9-]+\{(?:height|width):[0-9]", css), css[:500]
    assert "%" in css
    # The identical-404 page needs no nonce and keeps the base CSP.
    miss = _anon_client().get(f"/s/{'0' * 64}")
    assert miss.status_code == 404
    assert "'nonce-" not in miss.headers.get("content-security-policy", "")
    assert "style-src 'self';" in miss.headers.get("content-security-policy", "")
