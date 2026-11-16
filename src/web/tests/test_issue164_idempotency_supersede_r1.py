"""Issue #164 idempotency-supersede REMEDIATION 1: tests T11-T16.

Spec: issue-164-idempotency-supersede-remediation1-spec.md
(2026-11-14). Codex P1 on PR #186 (head 154dc39b): the §2a session
gate in attempt_product_checkout_session is an UNLOCKED read, and
both routes backfilled stripe_session_id AFTER attempt returned,
also unlocked — so a session id could land on the row in the window
between the gate read and the supersede lock, and
supersede_pending_product_purchase then marked the row failed
UNCONDITIONALLY, even though its Stripe session was open (buyer may
be paying) or complete (buyer paid). Settlement grants only on
pending, so that was paid-no-entitlement.

T11-T14 inject the backfill DETERMINISTICALLY into that window: a
monkeypatch wrapper around pb.supersede_pending_product_purchase
writes the session id onto the row (separate session, committed —
exactly what a concurrent request's backfill did on the old code)
immediately before the real supersede runs, i.e. after the gate
read and before the supersede decision. No test hopes for a race.
T15 exercises the coordinated backfill (I2) directly. T16 is the
regression guard for the original poisoned-row case.

Teeth: T11-T15 FAIL on 154dc39b and PASS on the remediated tree;
T16 passes on both (guard).
"""
import uuid

import test_issue164_phase_a as A
import test_issue164_idempotency_supersede as S

# Re-register the Phase A environment fixture in this module.
p164_env = A.p164_env

_WIN = "cs_window"


def _inject_backfill_in_window(monkeypatch, env, pid, session_id):
    """Deterministic interleaving control: the first time the
    attempt reaches for the supersede, a concurrent request's
    backfill lands first (session id written + committed via an
    independent DB session). Returns the injection state."""
    from app import models
    from app import product_billing as pb
    real = pb.supersede_pending_product_purchase
    state = {"done": False}

    def _wrapped(db, purchase_id):
        if not state["done"]:
            state["done"] = True
            with env.sessions() as other:
                row = other.get(models.ProductPurchase, pid)
                assert row is not None and row.status == "pending"
                row.stripe_session_id = session_id
                other.commit()
        return real(db, purchase_id)

    monkeypatch.setattr(
        pb, "supersede_pending_product_purchase", _wrapped)
    return state


def _setup_poisoned(p164_env, monkeypatch, session_entry):
    """Seed a session-less poisoned IR row, stub Stripe so its key
    raises idempotency_error and the window session retrieves as
    ``session_entry``; return (user_id, csrf, rid, pid, captured)."""
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    captured = S._stripe_post_poisoned(
        monkeypatch, poisoned_keys={S._key(pid)})
    if session_entry is not None:
        S._stripe_get_sessions(monkeypatch, {_WIN: session_entry})
    return user_id, csrf, rid, pid, captured


# ---------------------------------------------------------------------------
# T11: backfill-in-window, session OPEN -> no supersede, existing_open
# ---------------------------------------------------------------------------

def test_t11_window_backfill_open_session_not_superseded(p164_env, monkeypatch):
    user_id, csrf, rid, pid, captured = _setup_poisoned(
        p164_env, monkeypatch,
        {"id": _WIN, "status": "open",
         "url": f"https://checkout.stripe.com/pay/{_WIN}",
         "payment_status": "unpaid"})
    state = _inject_backfill_in_window(monkeypatch, p164_env, pid, _WIN)
    r = A._checkout(p164_env, rid, csrf)
    assert state["done"]  # the interleaving really was injected
    assert r.status_code == 200, r.text[:300]
    # B returns the existing-open outcome for the window session.
    assert r.json()["purchase_id"] == str(pid)
    assert r.json()["checkout_url"] == \
        f"https://checkout.stripe.com/pay/{_WIN}"
    # Exactly ONE Stripe create attempt (B's poisoned one): no
    # replacement session was created.
    assert [c["key"] for c in captured] == [S._key(pid)]
    rows = S._rows(p164_env, user_id)
    # No replacement row; the original row is NOT failed and carries
    # the live session id.
    assert rows == [(pid, "pending", _WIN)]


# ---------------------------------------------------------------------------
# T12: backfill-in-window, session COMPLETE -> already_complete
# ---------------------------------------------------------------------------

def test_t12_window_backfill_complete_session_not_superseded(p164_env, monkeypatch):
    user_id, csrf, rid, pid, captured = _setup_poisoned(
        p164_env, monkeypatch,
        {"id": _WIN, "status": "complete",
         "url": f"https://checkout.stripe.com/pay/{_WIN}",
         "payment_status": "paid"})
    state = _inject_backfill_in_window(monkeypatch, p164_env, pid, _WIN)
    r = A._checkout(p164_env, rid, csrf)
    assert state["done"]
    assert r.status_code == 200, r.text[:300]
    assert r.json()["purchase_id"] == str(pid)
    assert r.json()["session_status"] == "complete"
    assert [c["key"] for c in captured] == [S._key(pid)]
    rows = S._rows(p164_env, user_id)
    assert rows == [(pid, "pending", _WIN)]


# ---------------------------------------------------------------------------
# T13: backfill-in-window, retrieval fails -> fail closed (503)
# ---------------------------------------------------------------------------

def test_t13_window_backfill_unconfirmed_session_fails_closed(p164_env, monkeypatch):
    import httpx
    user_id, csrf, rid, pid, captured = _setup_poisoned(
        p164_env, monkeypatch, None)

    def _get_500(url, params=None, auth=None, headers=None, timeout=None):
        return S._Resp({"error": {"message": "mocked outage"}},
                       status_code=500)

    monkeypatch.setattr(httpx, "get", _get_500)
    state = _inject_backfill_in_window(monkeypatch, p164_env, pid, _WIN)
    r = A._checkout(p164_env, rid, csrf)
    assert state["done"]
    # Generic CheckoutError -> 503; row stays pending, no replacement.
    assert r.status_code == 503, r.text[:300]
    assert [c["key"] for c in captured] == [S._key(pid)]
    rows = S._rows(p164_env, user_id)
    assert rows == [(pid, "pending", _WIN)]


# ---------------------------------------------------------------------------
# T14: backfill-in-window, session EXPIRED -> supersede proceeds
# ---------------------------------------------------------------------------

def test_t14_window_backfill_expired_session_supersedes(p164_env, monkeypatch):
    import httpx
    user_id, csrf, rid, pid, captured = _setup_poisoned(
        p164_env, monkeypatch, "expired")
    # Teeth for the expired branch: the end state alone cannot
    # distinguish the trees (marking an expired-session row failed
    # is correct on both), so this test also asserts the I1
    # mechanism — the window session was RETRIEVED (consulted under
    # the supersede lock) before the mark. On 154dc39b the supersede
    # never retrieves it: zero GETs, and this assertion fails there.
    _stub_get = httpx.get
    gets = []

    def _counting_get(url, params=None, auth=None, headers=None,
                      timeout=None):
        gets.append(url)
        return _stub_get(url, params=params, auth=auth,
                         headers=headers, timeout=timeout)

    monkeypatch.setattr(httpx, "get", _counting_get)
    state = _inject_backfill_in_window(monkeypatch, p164_env, pid, _WIN)
    r = A._checkout(p164_env, rid, csrf)
    assert state["done"]
    assert r.status_code == 200, r.text[:300]
    new_id = r.json()["purchase_id"]
    assert new_id != str(pid)
    # Exactly as today: one retry under the replacement row's key.
    assert [c["key"] for c in captured] == [S._key(pid), S._key(new_id)]
    rows = S._rows(p164_env, user_id)
    assert len(rows) == 2
    by_id = {str(i): (s, sid) for i, s, sid in rows}
    assert by_id[str(pid)][0] == "failed"
    assert by_id[new_id][0] == "pending"
    assert by_id[new_id][1] is not None  # replacement session backfilled
    # I1 mechanism: the window session was consulted before the mark.
    assert any(url.endswith(f"/{_WIN}") for url in gets), gets


# ---------------------------------------------------------------------------
# T15: backfill-after-supersede writes nothing on the failed row (I2)
# ---------------------------------------------------------------------------

def test_t15_backfill_after_supersede_writes_nothing(p164_env, monkeypatch):
    from app import models
    from app import product_billing as pb
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    # Supersede the poisoned row (the R1 coordinated path), committed
    # — the state a late backfill would arrive into.
    with p164_env.sessions() as db:
        new_purchase = pb.supersede_pending_product_purchase(db, pid)
        new_id = new_purchase.id
        db.commit()
    # A create that succeeded at Stripe for the OLD row now tries to
    # backfill its session id onto the failed row.
    with p164_env.sessions() as db:
        wrote = pb.backfill_product_purchase_session(
            db, pid, session_id="cs_late",
            price_id=A.PRICE_ID)
        db.commit()
    assert wrote is False
    with p164_env.sessions() as db:
        old = db.get(models.ProductPurchase, pid)
        assert old.status == "failed"
        assert old.stripe_session_id is None  # I2: nothing written
        # No grant-relevant state changed: no entitlement, and the
        # replacement row is untouched by the late backfill.
        assert db.query(models.Entitlement).count() == 0
        new = db.get(models.ProductPurchase, new_id)
        assert new.status == "pending"
        assert new.stripe_session_id is None
    # Positive control: the same coordinated backfill DOES write on
    # the live pending replacement row.
    with p164_env.sessions() as db:
        wrote = pb.backfill_product_purchase_session(
            db, new_id, session_id="cs_new_live",
            price_id=A.PRICE_ID)
        db.commit()
    assert wrote is True
    with p164_env.sessions() as db:
        assert db.get(models.ProductPurchase,
                      new_id).stripe_session_id == "cs_new_live"


# ---------------------------------------------------------------------------
# T16: regression guard — the original poisoned-row case still
# supersedes and succeeds end-to-end (mirrors T1 on this file's own
# assertions so the guard is local to the remediation suite)
# ---------------------------------------------------------------------------

def test_t16_poisoned_row_still_supersedes_end_to_end(p164_env, monkeypatch):
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    captured = S._stripe_post_poisoned(
        monkeypatch, poisoned_keys={S._key(pid)})
    r = A._checkout(p164_env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    new_id = r.json()["purchase_id"]
    assert new_id != str(pid)
    assert uuid.UUID(new_id)
    assert [c["key"] for c in captured] == [S._key(pid), S._key(new_id)]
    rows = S._rows(p164_env, user_id)
    assert len(rows) == 2
    by_id = {str(i): (s, sid) for i, s, sid in rows}
    assert by_id[str(pid)][0] == "failed"
    assert by_id[new_id][0] == "pending"
    assert by_id[new_id][1] is not None
