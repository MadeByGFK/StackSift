"""Issue #107: shareable report links — FREE (APPROVED trim T1).

Sharing costs nothing, ever: no charge/consent/admission for create,
rotate, or revoke. Hash-only 256-bit tokens (auth.generate_token /
hash_token precedent), once-only reveal, free rotation as recovery,
one active token per report, generation fencing, identical 404 for
unknown/malformed/tampered/revoked/rotated/expired/deleted/corrupt.

T3: a PDF is reachable via the share link ONLY when a paid, unexpired
PDF Result exists; CSV/JSON are NOT shared in v1.
T4: public sharing is single-file only; compare/batch get 422 BEFORE
link creation.
"""

import copy
import json
import re
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from test_account_migrations import migrated_engine  # noqa: F401  (fixture)
from test_phase2b_paid_e2e import paid_env, _signup_verify_login, _http_balance  # noqa: F401

from app import auth, credits as C, main, models as M
from app.sample_data import SAMPLE_LOG


def _payload(filename="test.log", **overrides):
    payload = copy.deepcopy(main.analyze_upload("test.log", SAMPLE_LOG.encode()))
    payload["filename"] = filename
    payload.pop("current_user", None)
    payload.pop("csrf_token", None)
    payload.update(overrides)
    return payload


def _make_report(env, uid, *, filename="test.log", payload=None,
                 expires_in_days=7, result_type="analysis"):
    if payload is None:
        payload = _payload(filename)
    raw = json.dumps(payload, default=str)
    now = C._utcnow()
    with env.sessions() as db:
        r = M.Result(
            user_id=uid, free_request_id=uuid.uuid4().hex, type=result_type,
            storage_manifest=raw, integrity_digest=C.hash_input(raw.encode()),
            byte_count=len(raw.encode()),
            ready_at=now, expires_at=now + timedelta(days=expires_in_days),
        )
        db.add(r)
        db.commit()
        db.refresh(r)
        return r.id


def _anon_client():
    return TestClient(main.app, base_url="https://testserver",
                      raise_server_exceptions=False, client=("127.0.0.1", 50000))


def _create_share(env, rid, csrf, key="share-1"):
    return env.client.post(f"/reports/{rid}/share",
                           data={"csrf_token": csrf, "idempotency_key": key})


def _token_from(resp):
    url = resp.json()["share_url"]
    m = re.fullmatch(r"/s/([0-9a-f]{64})", url)
    assert m, f"bad share_url: {url}"
    return m.group(1)


def _setup_shared(env):
    email, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create_share(env, rid, csrf)
    assert resp.status_code == 200, resp.text[:400]
    return email, uid, csrf, rid, _token_from(resp)


def test_create_share_is_free_and_stores_hash_only(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create_share(env, rid, csrf)
    assert resp.status_code == 200, resp.text[:400]
    assert _http_balance(env) == 3  # FREE: no debit (T1)
    token = _token_from(resp)
    with env.sessions() as db:
        row = db.query(M.ReportSharing).filter(M.ReportSharing.result_id == rid).one()
        assert row.token_hash == auth.hash_token(token)
        assert row.token_hash != token
        assert row.generation == 1 and row.revoked_at is None
        blob = json.dumps([str(c) for c in row.__dict__.values()])
        assert token not in blob
        # No paid operation was created for the free share action.
        assert db.query(M.Operation).filter(M.Operation.user_id == uid).count() == 0
        assert C.verify_account_invariants(db, uid) == []


def test_shared_view_anonymous_no_owner_identity_or_controls(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    r = anon.get(f"/s/{token}")
    assert r.status_code == 200, r.text[:300]
    assert "test.log" in r.text
    assert email not in r.text
    assert str(rid) not in r.text
    assert "My Reports" not in r.text
    assert "Log out" not in r.text
    assert "csrf_token" not in r.text
    assert "/pdf" not in r.text
    assert "set-cookie" not in {k.lower() for k in r.headers.keys()}


def test_identical_404_for_all_invalid_tokens(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    baseline = anon.get(f"/s/{'0' * 64}")
    assert baseline.status_code == 404
    cases = {
        "malformed": anon.get("/s/not-a-token"),
        "short": anon.get("/s/abc123"),
        "tampered": anon.get(f"/s/{token[:-1]}{'0' if token[-1] != '0' else '1'}"),
        "unknown": anon.get(f"/s/{'f' * 64}"),
    }
    for name, resp in cases.items():
        assert resp.status_code == 404, name
        assert resp.content == baseline.content, name
        for h in ("cache-control", "x-robots-tag", "content-security-policy",
                  "referrer-policy"):
            assert resp.headers.get(h) == baseline.headers.get(h), (name, h)
    # Expired source -> identical 404 (no 410 leak on the public route).
    with env.sessions() as db:
        src = db.get(M.Result, rid)
        src.expires_at = C._utcnow() - timedelta(days=1)
        db.commit()
    expired = anon.get(f"/s/{token}")
    assert expired.status_code == 404 and expired.content == baseline.content


def test_revoke_is_free_idempotent_and_immediate(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    assert anon.get(f"/s/{token}").status_code == 200
    r = env.client.post(f"/reports/{rid}/share/revoke",
                        data={"csrf_token": csrf, "idempotency_key": "rev-1"})
    assert r.status_code == 200, r.text[:300]
    assert _http_balance(env) == 3
    assert anon.get(f"/s/{token}").status_code == 404
    # Idempotent: a second revoke (new key) still succeeds, still free.
    r2 = env.client.post(f"/reports/{rid}/share/revoke",
                         data={"csrf_token": csrf, "idempotency_key": "rev-2"})
    assert r2.status_code == 200
    assert _http_balance(env) == 3


def test_rotate_is_free_replaces_token_and_replay_does_not_rotate_again(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    r = env.client.post(f"/reports/{rid}/share/rotate",
                        data={"csrf_token": csrf, "idempotency_key": "rot-1"})
    assert r.status_code == 200, r.text[:400]
    assert _http_balance(env) == 3
    new_token = _token_from(r)
    assert new_token != token
    assert anon.get(f"/s/{token}").status_code == 404
    assert anon.get(f"/s/{new_token}").status_code == 200
    with env.sessions() as db:
        gen = db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).one().generation
    # Replaying the SAME rotation key must not rotate again.
    r2 = env.client.post(f"/reports/{rid}/share/rotate",
                         data={"csrf_token": csrf, "idempotency_key": "rot-1"})
    assert r2.status_code == 200
    assert "share_url" not in r2.json()
    with env.sessions() as db:
        assert db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).one().generation == gen
    assert anon.get(f"/s/{new_token}").status_code == 200


def test_create_replay_does_not_reveal_or_replace_token(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    r = _create_share(env, rid, csrf, key="share-1")
    assert r.status_code == 200
    assert "share_url" not in r.json()
    assert _http_balance(env) == 3
    assert anon.get(f"/s/{token}").status_code == 200


def test_share_create_on_compare_and_batch_rejected_422_before_creation(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid_cmp = _make_report(env, uid, result_type="comparison")
    r = _create_share(env, rid_cmp, csrf, key="share-cmp")
    assert r.status_code == 422, r.text[:400]
    batch_payload = _payload("batch.log", report_kind="batch")
    rid_batch = _make_report(env, uid, filename="batch.log", payload=batch_payload)
    r2 = _create_share(env, rid_batch, csrf, key="share-batch")
    assert r2.status_code == 422, r2.text[:400]
    with env.sessions() as db:
        assert db.query(M.ReportSharing).count() == 0


def test_share_actions_owner_only_and_csrf(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    _, uid2, csrf2 = _signup_verify_login(env)
    assert _create_share(env, rid, csrf2, key="share-foreign").status_code == 404
    # Back as the owner: bad CSRF is 403. (Second signup switched the
    # session cookie, so re-login as the owner first.)
    # Find owner email from DB.
    with env.sessions() as db:
        owner_email = db.get(M.User, uid).email
    env.client.post("/auth/login", data={"email": owner_email, "password": "TestPass123!x"})
    r = env.client.post(f"/reports/{rid}/share",
                        data={"csrf_token": "wrong", "idempotency_key": "share-csrf"})
    assert r.status_code == 403
    anon = _anon_client()
    r2 = anon.post(f"/reports/{rid}/share",
                   data={"csrf_token": "x", "idempotency_key": "share-anon"})
    assert r2.status_code == 401


def test_shared_pdf_only_when_paid_and_unexpired(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    # No paid PDF exists yet -> identical-style 404 on the PDF route.
    assert anon.get(f"/s/{token}/pdf").status_code == 404
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    got = anon.get(f"/s/{token}/pdf")
    assert got.status_code == 200, got.text[:300]
    assert got.content[:4] == b"%PDF"
    assert "application/pdf" in got.headers.get("content-type", "")
    # PDF shareability dies with the PDF Result's own expiry (T6).
    with env.sessions() as db:
        pdf_result = db.query(M.Result).filter(
            M.Result.user_id == uid, M.Result.type == "pdf").one()
        pdf_result.expires_at = C._utcnow() - timedelta(minutes=1)
        db.commit()
    assert anon.get(f"/s/{token}/pdf").status_code == 404
    # The text share itself is unaffected.
    assert anon.get(f"/s/{token}").status_code == 200


def test_csv_json_not_shared_in_v1(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    assert anon.get(f"/s/{token}/exports/csv").status_code == 404
    assert anon.get(f"/s/{token}/exports/json").status_code == 404


def test_public_view_mutates_nothing_and_token_selects_nothing_else(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    other = _make_report(env, uid, filename="other.log")
    with env.sessions() as db:
        before_exp = C._as_aware(db.get(M.Result, rid).expires_at)
        before_gen = db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).one().generation
    anon = _anon_client()
    r = anon.get(f"/s/{token}?result_id={other}")
    assert r.status_code == 200
    assert "test.log" in r.text and "other.log" not in r.text
    # The token grants nothing on owner routes (no redirect following:
    # the owner route bounces anonymous browsers to /login with a 303).
    from fastapi.testclient import TestClient as _TC
    nofollow = _TC(main.app, base_url="https://testserver",
                   raise_server_exceptions=False, client=("127.0.0.1", 50000),
                   follow_redirects=False)
    assert nofollow.get(f"/reports/{rid}").status_code == 303
    with env.sessions() as db:
        assert C._as_aware(db.get(M.Result, rid).expires_at) == before_exp
        assert db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).one().generation == before_gen


def test_shared_view_escapes_log_html(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    payload = _payload("evil.log")
    payload["sorted_issues"] = [
        ["<script>alert(1)</script>", {"level": "ERROR", "count": 1}]]
    payload["results"]["issues"] = {
        "<script>alert(1)</script>": {"level": "ERROR", "count": 1}}
    rid = _make_report(env, uid, filename="evil.log", payload=payload)
    resp = _create_share(env, rid, csrf)
    token = _token_from(resp)
    anon = _anon_client()
    r = anon.get(f"/s/{token}")
    assert r.status_code == 200, r.text[:300]
    assert "<script>alert" not in r.text
    assert "&lt;script&gt;" in r.text


def test_shared_headers_on_hit_and_miss(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    for resp in (anon.get(f"/s/{token}"), anon.get(f"/s/{'0' * 64}")):
        assert resp.headers.get("cache-control") == "private, no-store"
        assert resp.headers.get("referrer-policy") == "no-referrer"
        assert "noindex" in resp.headers.get("x-robots-tag", "")
        csp = resp.headers.get("content-security-policy", "")
        assert "frame-ancestors 'none'" in csp
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-content-type-options") == "nosniff"


def test_revoked_link_stays_revoked_after_extension(paid_env):
    """Extending a report never revives a revoked link (draft §3)."""
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    env.client.post(f"/reports/{rid}/share/revoke",
                    data={"csrf_token": csrf, "idempotency_key": "rev-x"})
    ext = env.client.post(f"/reports/{rid}/retention",
                          data={"csrf_token": csrf, "idempotency_key": "ext-x"})
    assert ext.status_code == 200, ext.text[:300]
    assert anon.get(f"/s/{token}").status_code == 404
    # ...but an active link follows the source's extended expiry.
    resp = _create_share(env, rid, csrf, key="share-again")
    assert resp.status_code == 200


def test_reshare_after_revoke_via_rotate(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    env.client.post(f"/reports/{rid}/share/revoke",
                    data={"csrf_token": csrf, "idempotency_key": "rev-y"})
    assert anon.get(f"/s/{token}").status_code == 404
    r = env.client.post(f"/reports/{rid}/share/rotate",
                        data={"csrf_token": csrf, "idempotency_key": "rot-y"})
    assert r.status_code == 200, r.text[:400]
    new_token = _token_from(r)
    assert anon.get(f"/s/{new_token}").status_code == 200
    assert anon.get(f"/s/{token}").status_code == 404
