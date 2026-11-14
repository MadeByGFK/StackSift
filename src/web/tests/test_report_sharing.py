"""Issue #107 shareable links, as reworked by issue #135.

Sharing costs nothing, ever: no charge/consent/admission for create,
rotate, or revoke. 256-bit tokens; public lookup is by the SHA-256
hash (the raw token is additionally stored for the owner's
Settings -> Report Access copyable-link list, #135). One active
token per (report, format); generation fencing; identical 404 for
unknown/malformed/tampered/revoked/rotated/expired/deleted/corrupt.

#135: GET /s/<token> serves the report FILE in the link's format
(the recipient web view is gone); TXT is the free default format;
PDF/JSON/CSV link creation requires the #129 export unlock —
PREMISE CHANGED by issue #164 Phase C (C8): that gate is removed,
all formats create free; token authority + identical 404 unchanged.
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
from test_phase2b_paid_e2e import paid_env, _signup_verify_login  # noqa: F401

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


def _db_balance(env, uid):
    """Balance read directly from the account row (Phase C re-base:
    /credits/balance is retired (410) and the signup grant is gone —
    a fresh user has balance 0; sharing stays free)."""
    with env.sessions() as db:
        acct = db.query(M.CreditAccount).filter(
            M.CreditAccount.user_id == uid).first()
        return acct.balance if acct else 0


def _seed_completed_pdf_artifact(env, uid, rid):
    """Seed a legacy completed PDF operation + stored artifact
    directly (Phase C: a free owner export creates neither), in the
    production shape — artifact Result origin-linked to its
    operation, operation pointing back via result_id."""
    import base64 as _b64

    from app.pdf_export import generate_report_pdf

    with env.sessions() as db:
        source = db.get(M.Result, rid)
        payload = C.result_payload(
            source, user_id=uid, operation_id=source.operation_id,
            free_request_id=source.free_request_id)
        filename = payload.get("filename", "test.log")
        pdf_bytes = generate_report_pdf(source.storage_manifest, filename)
        now = C._utcnow()
        op = M.Operation(
            user_id=uid, type="pdf", idempotency_key=f"pdf-{rid}",
            request_hash="a" * 64, cost=2, worker_id="seed-worker",
            lease_expires_at=now + timedelta(minutes=5),
            status="completed")
        db.add(op)
        db.flush()
        raw = json.dumps({
            "pdf_base64": _b64.b64encode(pdf_bytes).decode("ascii"),
            "filename": filename})
        artifact = M.Result(
            user_id=uid, operation_id=op.id, type="pdf",
            storage_manifest=raw,
            integrity_digest=C.hash_input(raw.encode()),
            byte_count=len(raw.encode()), ready_at=now,
            expires_at=now + timedelta(days=7))
        db.add(artifact)
        db.flush()
        op.result_id = artifact.id
        db.commit()
        return artifact.id


def _setup_shared(env):
    email, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create_share(env, rid, csrf)
    assert resp.status_code == 200, resp.text[:400]
    return email, uid, csrf, rid, _token_from(resp)


def test_create_share_is_free_and_stores_hash_only(paid_env):
    """PREMISE CHANGED (issue #135): Settings -> Report Access must
    list a copyable live link, which hash-only storage cannot
    redisplay — the row now ALSO stores the raw token in its
    dedicated raw_token column for owner-only Settings display.
    The lookup hash, generation fencing and free-ness are unchanged."""
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    resp = _create_share(env, rid, csrf)
    assert resp.status_code == 200, resp.text[:400]
    assert _db_balance(env, uid) == 0  # FREE: no debit (T1); Phase C: no signup grant
    token = _token_from(resp)
    with env.sessions() as db:
        row = db.query(M.ReportSharing).filter(M.ReportSharing.result_id == rid).one()
        assert row.token_hash == auth.hash_token(token)
        assert row.token_hash != token
        assert row.raw_token == token  # #135: Settings redisplay only
        assert row.share_format == "txt"  # default format
        assert row.generation == 1 and row.revoked_at is None
        # No paid operation was created for the free share action.
        assert db.query(M.Operation).filter(M.Operation.user_id == uid).count() == 0
        assert C.verify_account_invariants(db, uid) == []


def test_shared_view_anonymous_no_owner_identity_or_controls(paid_env):
    """PREMISE CHANGED (issue #135): the recipient web view is gone —
    the default (txt) link serves the plain-text report FILE. The
    anonymity assertions carry over to the file body/headers."""
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    r = anon.get(f"/s/{token}")
    assert r.status_code == 200, r.text[:300]
    assert r.headers["content-type"].startswith("text/plain")
    assert "attachment" in r.headers.get("content-disposition", "")
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
    assert _db_balance(env, uid) == 0
    assert anon.get(f"/s/{token}").status_code == 404
    # Idempotent: a second revoke (new key) still succeeds, still free.
    r2 = env.client.post(f"/reports/{rid}/share/revoke",
                         data={"csrf_token": csrf, "idempotency_key": "rev-2"})
    assert r2.status_code == 200
    assert _db_balance(env, uid) == 0


def test_rotate_is_free_replaces_token_and_replay_does_not_rotate_again(paid_env):
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    r = env.client.post(f"/reports/{rid}/share/rotate",
                        data={"csrf_token": csrf, "idempotency_key": "rot-1"})
    assert r.status_code == 200, r.text[:400]
    assert _db_balance(env, uid) == 0
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
    assert _db_balance(env, uid) == 0
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
    """PREMISE CHANGED (issue #135): a PDF is shared through a
    pdf-FORMAT link, not a subroute of a text link. Creation is
    blocked pre-unlock; post-unlock the pdf link serves the PDF;
    the PDF artifact's own expiry (T6) still kills it, while the
    txt link is unaffected.

    PREMISE CHANGED AGAIN (issue #164 Phase C, C8): the unlock gate
    is REMOVED — a pdf link creates free with no unlock, and with no
    completed PDF operation the shared PDF is generated on the fly
    (C7.1). The T6 leg is preserved via a seeded completed operation
    + stored artifact: once that artifact expires, the share dies
    (no regeneration), while the txt link is unaffected."""
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    # The txt link does not serve PDF at the old subroute.
    assert anon.get(f"/s/{token}/pdf").status_code == 404
    # No gate: creating a pdf link succeeds immediately, free.
    created = env.client.post(
        f"/reports/{rid}/share",
        data={"csrf_token": csrf, "idempotency_key": "pdf-link-1",
              "format": "pdf"})
    assert created.status_code == 200, created.text[:300]
    assert _db_balance(env, uid) == 0
    pdf_token = _token_from(created)
    # The owner's own PDF export is free too and stores nothing.
    pdf = env.client.post(f"/reports/{rid}/pdf", data={"csrf_token": csrf})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    got = anon.get(f"/s/{pdf_token}")
    assert got.status_code == 200, got.text[:300]
    assert got.content[:4] == b"%PDF"
    assert "application/pdf" in got.headers.get("content-type", "")
    # The legacy subroute works for a pdf-format link too.
    assert anon.get(f"/s/{pdf_token}/pdf").content[:4] == b"%PDF"
    # PDF shareability dies with the PDF Result's own expiry (T6):
    # seed the completed operation + artifact, then expire it.
    _seed_completed_pdf_artifact(env, uid, rid)
    with env.sessions() as db:
        pdf_result = db.query(M.Result).filter(
            M.Result.user_id == uid, M.Result.type == "pdf").one()
        pdf_result.expires_at = C._utcnow() - timedelta(minutes=1)
        db.commit()
    assert anon.get(f"/s/{pdf_token}").status_code == 404
    assert anon.get(f"/s/{pdf_token}/pdf").status_code == 404
    # The text share itself is unaffected.
    assert anon.get(f"/s/{token}").status_code == 200


def test_csv_json_not_shared_in_v1(paid_env):
    """PREMISE CHANGED (issue #135): CSV/JSON ARE shared now — but
    only through their own format links. The old per-format
    subroutes of a txt link still serve nothing."""
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
    """PREMISE CHANGED (issue #135): there is no shared web page to
    inject into — the txt link serves text/plain, so log HTML is
    inert file content, delivered with a non-HTML content type and
    an attachment disposition (never rendered as markup)."""
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
    assert r.headers["content-type"].startswith("text/plain")
    assert "attachment" in r.headers.get("content-disposition", "")
    assert "<html" not in r.text.lower()


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
    """Extending a report never revives a revoked link (draft §3).

    PREMISE CHANGED (issue #164 Phase C, Decision 5 / C5): a new
    retention extension can no longer be bought (410, no mutation) —
    the revoked link stays revoked either way, and a fresh share
    still creates under the source's existing window."""
    env = paid_env
    email, uid, csrf, rid, token = _setup_shared(env)
    anon = _anon_client()
    env.client.post(f"/reports/{rid}/share/revoke",
                    data={"csrf_token": csrf, "idempotency_key": "rev-x"})
    with env.sessions() as db:
        before_expiry = db.get(M.Result, rid).expires_at
    ext = env.client.post(f"/reports/{rid}/retention",
                          data={"csrf_token": csrf, "idempotency_key": "ext-x"})
    assert ext.status_code == 410, ext.text[:300]
    assert "no longer sold" in ext.json()["error"]
    with env.sessions() as db:
        assert db.get(M.Result, rid).expires_at == before_expiry
    assert anon.get(f"/s/{token}").status_code == 404
    # ...and a fresh active link still creates and serves.
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


# --- Share-action owner rate limit (10/hour, policy "share:actions") ---


def _rotate(env, rid, csrf, key):
    return env.client.post(f"/reports/{rid}/share/rotate",
                           data={"csrf_token": csrf, "idempotency_key": key})


def _sharing_state(env, rid):
    with env.sessions() as db:
        row = db.query(M.ReportSharing).filter(
            M.ReportSharing.result_id == rid).one()
        return row.generation, row.token_hash


def _share_action_count(env, uid, rid):
    with env.sessions() as db:
        return db.query(M.ReportAction).filter(
            M.ReportAction.owner_user_id == uid,
            M.ReportAction.result_id == rid,
            M.ReportAction.action_kind.in_(
                ("share_create", "share_rotate", "share_revoke"))).count()


def _exhaust_share_limit(env, rid, csrf, prefix):
    """Drive exactly 10 distinct share actions: 1 create + 9 rotates."""
    resp = _create_share(env, rid, csrf, key=f"{prefix}-create")
    assert resp.status_code == 200, resp.text[:400]
    last_token = _token_from(resp)
    for i in range(9):
        r = _rotate(env, rid, csrf, f"{prefix}-rot-{i}")
        assert r.status_code == 200, r.text[:400]
        last_token = _token_from(r)
    return last_token


def test_share_actions_rate_limited_11th_distinct_action_429_no_mutation(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    last_token = _exhaust_share_limit(env, rid, csrf, "rl-a")
    gen_before, hash_before = _sharing_state(env, rid)
    assert _share_action_count(env, uid, rid) == 10
    # The 11th distinct share action in the window is rate-limited.
    r = _rotate(env, rid, csrf, "rl-a-rot-9")
    assert r.status_code == 429, r.text[:400]
    assert r.json() == {"error": "Too many share actions. Please try again later."}
    # No mutation persisted: active token + generation unchanged, and
    # no new ReportAction row for the rate-limited attempt.
    gen_after, hash_after = _sharing_state(env, rid)
    assert (gen_after, hash_after) == (gen_before, hash_before)
    assert hash_after == auth.hash_token(last_token)
    assert _share_action_count(env, uid, rid) == 10
    assert _db_balance(env, uid) == 0  # still FREE: no debit
    assert _anon_client().get(f"/s/{last_token}").status_code == 200


def test_share_action_replay_at_limit_returns_stored_outcome_without_consuming(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    _exhaust_share_limit(env, rid, csrf, "rl-b")
    # Prove the limit is actually reached (this assertion is what
    # fails on a tree with no share-action rate bucket).
    blocked = _rotate(env, rid, csrf, "rl-b-rot-9")
    assert blocked.status_code == 429, blocked.text[:400]
    gen_before, hash_before = _sharing_state(env, rid)
    assert _share_action_count(env, uid, rid) == 10
    # Replaying an earlier rotate key at/over the limit still returns
    # its stored outcome (200, no new token) and consumes no rate.
    replay = _rotate(env, rid, csrf, "rl-b-rot-0")
    assert replay.status_code == 200, replay.text[:400]
    assert replay.json().get("status") == "already_rotated"
    assert "share_url" not in replay.json()
    # Replaying the original create key likewise returns its outcome.
    replay_create = _create_share(env, rid, csrf, key="rl-b-create")
    assert replay_create.status_code == 200, replay_create.text[:400]
    assert replay_create.json().get("status") == "already_shared"
    assert "share_url" not in replay_create.json()
    assert _sharing_state(env, rid) == (gen_before, hash_before)
    assert _share_action_count(env, uid, rid) == 10
    # A further distinct action is still rate-limited afterwards.
    assert _rotate(env, rid, csrf, "rl-b-rot-10").status_code == 429


def test_share_action_rate_limit_is_per_owner(paid_env):
    env = paid_env
    _, uid, csrf = _signup_verify_login(env)
    rid = _make_report(env, uid)
    _exhaust_share_limit(env, rid, csrf, "rl-c")
    # First owner is at the limit (fails on a tree with no bucket).
    assert _rotate(env, rid, csrf, "rl-c-rot-9").status_code == 429
    # A second owner is unaffected by the first owner's bucket.
    _, uid2, csrf2 = _signup_verify_login(env)
    rid2 = _make_report(env, uid2)
    resp = _create_share(env, rid2, csrf2, key="rl-c-owner2-create")
    assert resp.status_code == 200, resp.text[:400]
    token2 = _token_from(resp)
    assert _anon_client().get(f"/s/{token2}").status_code == 200
    assert _share_action_count(env, uid2, rid2) == 1
