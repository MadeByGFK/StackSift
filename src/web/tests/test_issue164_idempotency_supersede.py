"""Issue #164 idempotency-supersede fix: required tests T1-T10.

Spec: issue-164-idempotency-supersede-spec.md (2026-11-14). A pending
ProductPurchase whose Stripe idempotency key was first used with a
different parameter set is poisoned: Stripe rejects every retry on
that key with HTTP 400 ``error.type == "idempotency_error"`` and the
row can never succeed. The fix distinguishes that error, and — only
when safe (no live session on the row, or its session is
conclusively expired) — supersedes the row ONCE and retries ONCE
under a new purchase row / new key.

Runtime/route-level tests: mocked Stripe HTTP layer (httpx.post /
httpx.get, the house pattern from test_issue164_phase_a/b), real
routes + real DB state. These tests FAIL on the pre-build tree
(4aa3df19: every idempotency_error collapses to a generic 503) and
PASS on the built tree.
"""
import hashlib
import threading
import uuid

import pytest

import test_issue164_phase_a as A
import test_issue164_phase_b as B

# Re-register the Phase A / Phase B environment fixtures in this
# module (imported fixture objects keep their pytest registration).
p164_env = A.p164_env
p164b_env = B.p164b_env


# ---------------------------------------------------------------------------
# Mocked Stripe HTTP layer
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, payload, status_code=200):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


_IDEM_ERROR = {
    "error": {
        "type": "idempotency_error",
        "code": "idempotency_error",
        "message": ("Keys for idempotent requests can only be used "
                    "with the same parameters they were first used "
                    "with."),
    }
}


def _key(purchase_id):
    return f"checkout:product:{purchase_id}"


def _stripe_post_poisoned(monkeypatch, *, poisoned_keys=(), poison_all=False):
    """httpx.post stub: poisoned idempotency keys -> HTTP 400
    idempotency_error; every other key creates a session, and (like
    real Stripe idempotency) a repeat POST under the same key returns
    the SAME session. Returns the captured calls."""
    import httpx
    captured = []
    sessions_by_key = {}
    lock = threading.Lock()
    state = {"n": 0}

    def _post(url, data=None, auth=None, headers=None, timeout=None):
        key = (headers or {}).get("Idempotency-Key")
        with lock:
            captured.append({"url": url, "data": data or {},
                             "headers": headers, "key": key})
            if poison_all or key in poisoned_keys:
                return _Resp(dict(_IDEM_ERROR), status_code=400)
            if key in sessions_by_key:
                return _Resp(sessions_by_key[key])
            state["n"] += 1
            sid = f"cs_new_{state['n']}"
            payload = {"url": f"https://checkout.stripe.com/pay/{sid}",
                       "id": sid}
            sessions_by_key[key] = payload
            return _Resp(payload)

    monkeypatch.setattr(httpx, "post", _post)
    return captured


def _stripe_get_sessions(monkeypatch, sessions_by_id, *, line_price=None):
    """httpx.get stub serving Checkout Session retrievals by id
    (values are a status string or a full session dict) plus the
    line-items endpoint settlement uses."""
    import httpx

    def _get(url, params=None, auth=None, headers=None, timeout=None):
        if url.endswith("/line_items"):
            if line_price is None:
                return _Resp({"data": []})
            return _Resp({"data": [{"price": {"id": line_price}}]})
        sid = url.rsplit("/", 1)[-1]
        assert sid in sessions_by_id, url
        entry = sessions_by_id[sid]
        if isinstance(entry, str):
            entry = {"id": sid, "status": entry,
                     "url": f"https://checkout.stripe.com/pay/{sid}",
                     "payment_status": "unpaid" if entry == "open" else None}
        return _Resp(entry)

    monkeypatch.setattr(httpx, "get", _get)


def _seed_digest_purchase(env, user_id, sku, digest, *, session_id=None):
    from app import models
    with env.sessions() as db:
        p = models.ProductPurchase(
            user_id=user_id, sku=sku, content_digest=digest,
            stripe_session_id=session_id,
            amount_cents=500, currency="usd",
            stripe_price_id=B.PRICE_BY_SKU[sku],
            pricing_version=1, status="pending")
        db.add(p)
        db.commit()
        db.refresh(p)
        return p.id


def _rows(env, user_id=None):
    from app import models
    with env.sessions() as db:
        q = db.query(models.ProductPurchase)
        if user_id is not None:
            q = q.filter(models.ProductPurchase.user_id == user_id)
        return [(p.id, p.status, p.stripe_session_id)
                for p in q.order_by(models.ProductPurchase.created_at).all()]


# ---------------------------------------------------------------------------
# T1 / T2: poisoned rows (no session id) supersede + retry once
# ---------------------------------------------------------------------------

def test_t1_poisoned_ir_row_superseded_retry_succeeds(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    captured = _stripe_post_poisoned(monkeypatch, poisoned_keys={_key(pid)})
    r = A._checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    new_id = r.json()["purchase_id"]
    assert new_id != str(pid)
    assert r.json()["checkout_url"]
    # Exactly two Stripe attempts: the poisoned key, then the NEW
    # row's key — and the returned session was created under the new
    # key.
    assert [c["key"] for c in captured] == [_key(pid), _key(new_id)]
    rows = _rows(p164_env, user_id)
    assert len(rows) == 2
    by_id = {str(i): (s, sid) for i, s, sid in rows}
    assert by_id[str(pid)][0] == "failed"          # old row superseded
    assert by_id[new_id][0] == "pending"           # new row live
    assert by_id[new_id][1] is not None            # session backfilled


def test_t2_poisoned_digest_row_superseded_retry_succeeds(p164b_env, monkeypatch):
    _, user_id, csrf = B._make_user(p164b_env)
    digest = hashlib.sha256(b"t2-compare-content").hexdigest()
    pid = _seed_digest_purchase(p164b_env, user_id, "compare", digest)
    captured = _stripe_post_poisoned(monkeypatch, poisoned_keys={_key(pid)})
    r = B._checkout(p164b_env, csrf, "compare", digest)
    assert r.status_code == 200, r.text[:300]
    new_id = r.json()["purchase_id"]
    assert new_id != str(pid)
    assert [c["key"] for c in captured] == [_key(pid), _key(new_id)]
    # The replacement session's success URL binds the return landing
    # to the NEW purchase (§5), not the poisoned row.
    assert f"purchase={new_id}" in captured[1]["data"]["success_url"]
    rows = _rows(p164b_env, user_id)
    assert len(rows) == 2
    by_id = {str(i): s for i, s, _sid in rows}
    assert by_id[str(pid)] == "failed"
    assert by_id[new_id] == "pending"


# ---------------------------------------------------------------------------
# T3 / T4: rows WITH a session id — retrieve first, supersede only
# on conclusive expiry
# ---------------------------------------------------------------------------

def test_t3_session_id_row_open_session_returned_no_supersede(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id="cs_old")
    captured = _stripe_post_poisoned(monkeypatch, poison_all=True)
    _stripe_get_sessions(monkeypatch, {
        "cs_old": {"id": "cs_old", "status": "open",
                   "url": "https://checkout.stripe.com/pay/cs_old",
                   "payment_status": "unpaid"}})
    r = A._checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    assert r.json()["purchase_id"] == str(pid)
    assert r.json()["checkout_url"] == "https://checkout.stripe.com/pay/cs_old"
    assert len(captured) == 1  # one create attempt; retrieval, no retry
    rows = _rows(p164_env, user_id)
    assert len(rows) == 1 and rows[0][1] == "pending"  # NO new row


def test_t4_session_id_row_conclusively_expired_supersedes(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id="cs_old")
    captured = _stripe_post_poisoned(monkeypatch, poisoned_keys={_key(pid)})
    _stripe_get_sessions(monkeypatch, {"cs_old": "expired"})
    r = A._checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    new_id = r.json()["purchase_id"]
    assert new_id != str(pid)
    assert [c["key"] for c in captured] == [_key(pid), _key(new_id)]
    rows = _rows(p164_env, user_id)
    assert len(rows) == 2
    by_id = {str(i): s for i, s, _sid in rows}
    assert by_id[str(pid)] == "failed"
    assert by_id[new_id] == "pending"


# ---------------------------------------------------------------------------
# T5 / T6: failure discipline
# ---------------------------------------------------------------------------

def test_t5_double_failure_503_exactly_one_supersede(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    captured = _stripe_post_poisoned(monkeypatch, poison_all=True)
    r = A._checkout(p164_env, rid, csrf)
    assert r.status_code == 503, r.text[:300]
    # Exactly two attempts (original + one supersede retry), no loop.
    assert len(captured) == 2
    assert captured[0]["key"] == _key(pid)
    assert captured[1]["key"] != _key(pid)
    rows = _rows(p164_env, user_id)
    # Old failed + exactly ONE new row, no third row.
    assert len(rows) == 2
    assert sorted(s for _i, s, _sid in rows) == ["failed", "pending"]
    new_ids = [str(i) for i, s, _sid in rows if str(i) != str(pid)]
    assert captured[1]["key"] == _key(new_ids[0])


def test_t6_non_idempotency_failure_no_supersede_same_key_retry(p164_env, monkeypatch):
    import httpx
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    captured = []
    state = {"n": 0}

    def _post(url, data=None, auth=None, headers=None, timeout=None):
        captured.append({"url": url, "data": data or {}, "headers": headers,
                         "key": (headers or {}).get("Idempotency-Key")})
        state["n"] += 1
        if state["n"] == 1:
            return _Resp({"error": {
                "type": "invalid_request_error",
                "code": "parameter_invalid",
                "param": "line_items[0][price]",
                "message": "Invalid price (mocked)."}}, status_code=400)
        return _Resp({"url": "https://checkout.stripe.com/pay/cs_retry",
                      "id": "cs_retry"})

    monkeypatch.setattr(httpx, "post", _post)
    # Billing-layer leg (§1): the distinction itself — an
    # invalid_request_error raises the plain CheckoutError and must
    # NOT be the idempotency subclass, while an idempotency_error
    # body raises exactly the subclass. (On the pre-build tree the
    # subclass does not exist, so this leg fails there.)
    from app import stripe_billing

    def _direct(error_payload):
        monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(
            error_payload, status_code=400))
        return stripe_billing.create_product_checkout_session(
            user_id=user_id, sku="investigation_report",
            purchase_id=uuid.uuid4(),
            success_url="https://example.test/ok",
            cancel_url="https://example.test/no")

    with pytest.raises(stripe_billing.CheckoutError) as plain:
        _direct({"error": {"type": "invalid_request_error",
                           "message": "Invalid (mocked)."}})
    assert not isinstance(plain.value,
                          stripe_billing.CheckoutIdempotencyError)
    with pytest.raises(stripe_billing.CheckoutIdempotencyError):
        _direct(dict(_IDEM_ERROR))
    monkeypatch.setattr(httpx, "post", _post)
    r1 = A._checkout(p164_env, rid, csrf)
    assert r1.status_code == 503, r1.text[:300]
    rows = _rows(p164_env, user_id)
    assert len(rows) == 1 and rows[0][1] == "pending"  # NO supersede
    # Next retry reuses the SAME row and the SAME key, and succeeds
    # with the session created under that key (A7/P2-1 intact).
    r2 = A._checkout(p164_env, rid, csrf)
    assert r2.status_code == 200, r2.text[:300]
    assert r2.json()["purchase_id"] == str(pid)
    assert [c["key"] for c in captured] == [_key(pid), _key(pid)]
    rows = _rows(p164_env, user_id)
    assert len(rows) == 1 and rows[0][2] == "cs_retry"


# ---------------------------------------------------------------------------
# T7: concurrent double-submit on a poisoned binding
# ---------------------------------------------------------------------------

def test_t7_concurrent_double_submit_one_row_one_session(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    # Force both submissions to be inside the poisoned create call at
    # the same time before either can supersede.
    barrier = threading.Barrier(2)
    import httpx
    captured = []
    sessions_by_key = {}
    lock = threading.Lock()
    state = {"n": 0}

    def _post(url, data=None, auth=None, headers=None, timeout=None):
        key = (headers or {}).get("Idempotency-Key")
        with lock:
            captured.append({"key": key})
        if key == _key(pid):
            try:
                barrier.wait(timeout=15)
            except threading.BrokenBarrierError:
                pass
            return _Resp(dict(_IDEM_ERROR), status_code=400)
        with lock:
            if key in sessions_by_key:
                return _Resp(sessions_by_key[key])
            state["n"] += 1
            sid = f"cs_race_{state['n']}"
            payload = {"url": f"https://checkout.stripe.com/pay/{sid}",
                       "id": sid}
            sessions_by_key[key] = payload
            return _Resp(payload)

    monkeypatch.setattr(httpx, "post", _post)
    results = {}

    def _submit(tag):
        try:
            results[tag] = A._checkout(p164_env, rid, csrf)
        except Exception as exc:  # surfaced by the assertions below
            results[tag] = exc

    threads = [threading.Thread(target=_submit, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert all(not t.is_alive() for t in threads)
    r0, r1 = results[0], results[1]
    assert not isinstance(r0, Exception), repr(r0)
    assert not isinstance(r1, Exception), repr(r1)
    assert r0.status_code == 200, r0.text[:300]
    assert r1.status_code == 200, r1.text[:300]
    # Both responses reference the SAME (new) purchase and session.
    assert r0.json()["purchase_id"] == r1.json()["purchase_id"] != str(pid)
    assert r0.json()["checkout_url"] == r1.json()["checkout_url"]
    rows = _rows(p164_env, user_id)
    live = [row for row in rows if row[1] == "pending"]
    assert len(live) == 1                      # exactly ONE live pending row
    assert str(live[0][0]) == r0.json()["purchase_id"]
    assert sorted(s for _i, s, _sid in rows) == ["failed", "pending"]
    assert len(sessions_by_key) == 1           # exactly ONE session created


# ---------------------------------------------------------------------------
# T8: settlement safety — superseded row grants nothing, new row
# grants exactly once
# ---------------------------------------------------------------------------

def test_t8_settlement_old_grants_nothing_new_grants_once(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    _stripe_post_poisoned(monkeypatch, poisoned_keys={_key(pid)})
    r = A._checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    new_id = uuid.UUID(r.json()["purchase_id"])
    A._stub_stripe_get_combined(monkeypatch)
    from app import models
    with p164_env.sessions() as db:
        old = db.get(models.ProductPurchase, pid)
        new = db.get(models.ProductPurchase, new_id)
        old_ref = A.SimpleNamespace(id=old.id, user_id=old.user_id)
        new_ref = A.SimpleNamespace(id=new.id, user_id=new.user_id)
        new_session = new.stripe_session_id
    # Webhook naming the OLD (superseded/failed) purchase: the event
    # is a duplicate/terminal no-op — no entitlement, no grant.
    ev_old = A._product_completed_event(
        "evt_t8_old", old_ref, session_id="cs_poisoned_old")
    resp_old = A._post_event(p164_env, ev_old)
    assert resp_old.status_code == 200, resp_old.text[:300]
    assert resp_old.json()["status"] == "duplicate"
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0
        assert db.get(models.ProductPurchase, pid).status == "failed"
    # Webhook for the NEW purchase settles and grants exactly once;
    # duplicate delivery grants nothing twice.
    ev_new = A._product_completed_event(
        "evt_t8_new", new_ref, session_id=new_session,
        pi="pi_t8_new")
    resp_new = A._post_event(p164_env, ev_new)
    assert resp_new.json()["status"] == "processed"
    resp_dup = A._post_event(p164_env, ev_new)
    assert resp_dup.json()["status"] == "duplicate"
    with p164_env.sessions() as db:
        ents = db.query(models.Entitlement).all()
        assert len(ents) == 1
        assert ents[0].product_purchase_id == new_id
        assert db.get(models.ProductPurchase, new_id).status == "completed"


# ---------------------------------------------------------------------------
# T9: displayed state after mutation
# ---------------------------------------------------------------------------

def test_t9_investigation_status_reflects_new_row(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    _stripe_post_poisoned(monkeypatch, poisoned_keys={_key(pid)})
    r = A._checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    new_id = r.json()["purchase_id"]
    # The status surface orders by created_at desc: after the
    # supersede it must show the NEW row's pending status. (If it
    # read the poisoned row it would show 'failed'.)
    st = p164_env.client.get(f"/reports/{rid}/investigation-status")
    assert st.status_code == 200
    assert st.json()["purchase_status"] == "pending"
    assert st.json()["entitlement_status"] is None
    # And once the new row settles, the same surface shows the
    # entitlement — still nothing stale from the poisoned row.
    A._stub_stripe_get_combined(monkeypatch)
    from app import models
    with p164_env.sessions() as db:
        new = db.get(models.ProductPurchase, uuid.UUID(new_id))
        new_ref = A.SimpleNamespace(id=new.id, user_id=new.user_id)
        new_session = new.stripe_session_id
    ev = A._product_completed_event("evt_t9", new_ref,
                                    session_id=new_session, pi="pi_t9")
    assert A._post_event(p164_env, ev).json()["status"] == "processed"
    st2 = p164_env.client.get(f"/reports/{rid}/investigation-status")
    assert st2.json()["entitlement_status"] == "available"


# ---------------------------------------------------------------------------
# T10: replay through the second control — a poisoned IR binding
# does not touch other bindings
# ---------------------------------------------------------------------------

def test_t10_compare_checkout_unaffected_by_ir_supersede(p164b_env, monkeypatch):
    # One env carries both surfaces (Phase B fixture configures the
    # IR price too): poison + supersede an IR purchase, then run a
    # Compare checkout for the same user — it must create its own
    # row/session normally, with no cross-binding supersede.
    _, user_id, csrf = B._make_user(p164b_env)
    rid = A._source(p164b_env, user_id)
    pid = A._seed_purchase(p164b_env, user_id, rid, status="pending",
                           session_id=None)
    # Phase B env snapshots its own IR price id on seeded rows via
    # A's helper (A.PRICE_ID); align the row's snapshot with this
    # env's configured price so only the idempotency behaviour is
    # exercised here.
    from app import models
    with p164b_env.sessions() as db:
        row = db.get(models.ProductPurchase, pid)
        row.stripe_price_id = B.PRICE_BY_SKU["investigation_report"]
        db.commit()
    captured = _stripe_post_poisoned(monkeypatch, poisoned_keys={_key(pid)})
    r = p164b_env.client.post(f"/reports/{rid}/investigation-checkout",
                              data={"csrf_token": csrf})
    assert r.status_code == 200, r.text[:300]
    ir_new_id = r.json()["purchase_id"]
    assert ir_new_id != str(pid)
    # Second control: Compare checkout for a fresh digest.
    digest = hashlib.sha256(b"t10-compare-content").hexdigest()
    r2 = B._checkout(p164b_env, csrf, "compare", digest)
    assert r2.status_code == 200, r2.text[:300]
    compare_id = r2.json()["purchase_id"]
    assert compare_id not in (str(pid), ir_new_id)
    # The compare attempt used ONLY its own new key — no supersede
    # retry (a single create call for that purchase).
    compare_calls = [c for c in captured if c["key"] == _key(compare_id)]
    assert len(compare_calls) == 1
    with p164b_env.sessions() as db:
        compare_row = db.get(models.ProductPurchase, uuid.UUID(compare_id))
        assert compare_row.status == "pending"
        assert compare_row.sku == "compare"
        assert compare_row.content_digest == digest
        assert compare_row.stripe_session_id is not None
        # IR rows untouched by the compare checkout.
        assert db.get(models.ProductPurchase, pid).status == "failed"
        assert db.get(models.ProductPurchase,
                      uuid.UUID(ir_new_id)).status == "pending"
