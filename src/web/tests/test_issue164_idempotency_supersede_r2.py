"""Issue #164 idempotency-supersede REMEDIATION 2: tests T17-T20.

Spec: issue-164-idempotency-supersede-remediation2-spec.md
(2026-11-14). Codex re-review of PR #186 head 6f06868e landed two
findings, both verified by Sunny against the tree:

F1 (P1): attempt_product_checkout_session ignored the return of
backfill_product_purchase_session on BOTH create paths, and both
routes ignored their re-application too — so when a concurrent
request superseded the row first (backfill correctly returns False,
T15), the loser still returned state "created" with the ORIGINAL,
still-payable checkout URL for a row that is no longer pending.
Settlement grants only on pending rows: paid-no-entitlement.

F2 (P2): already_complete answered checkout_url = session.url,
which is null for a complete Stripe session, and neither handler in
paid_consent.html handles session_status — a buyer who had already
paid and retried before the webhook settled was told "Checkout is
unavailable right now." instead of being routed to the
settlement-aware, purchase-bound return landing.

T17/T18 inject the competing supersede DETERMINISTICALLY into the
backfill window: a monkeypatch wrapper around
pb.backfill_product_purchase_session first releases the attempt's
read transaction, then runs the REAL supersede on an independent DB
session and commits it (exactly request B's committed supersede in
the F1 narrative), and only then calls the real backfill. No test
hopes for a race. T19 is route-level on both checkout routes plus a
runtime/DOM-level (Node) exercise of BOTH paid_consent.html checkout
handlers. T20 is the positive control guarding J1 against
over-blocking (the R1 T16 pattern: a guard passes on both trees).

Teeth: T17-T19 FAIL on 6f06868e and PASS on the R2 tree; T20 passes
on both (guard).
"""
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import test_issue164_phase_a as A
import test_issue164_phase_b as B
import test_issue164_idempotency_supersede as S

# Re-register the Phase A / Phase B environment fixtures in this
# module (the R1 file's pattern).
p164_env = A.p164_env
p164b_env = B.p164b_env


def _inject_supersede_before_backfill(monkeypatch, env):
    """Deterministic F1 interleaving control: the FIRST coordinated
    backfill call is preceded by request B's committed supersede of
    the same row (real supersede, independent DB session, committed),
    so the real backfill lands after the supersede — the T15 state,
    injected at the exact window F1 names. Returns the state dict;
    state["target"] is the purchase id whose backfill lost and
    state["new_id"] is B's replacement row."""
    from app import product_billing as pb
    real_backfill = pb.backfill_product_purchase_session
    real_supersede = pb.supersede_pending_product_purchase
    state = {"done": False, "target": None, "new_id": None}

    def _wrapped(db, purchase_id, *, session_id, price_id=None):
        if not state["done"]:
            state["done"] = True
            state["target"] = purchase_id
            # Release the attempt session's read transaction so B's
            # independent commit is not blocked by it (SQLite); the
            # attempt has written nothing at this point on either
            # create path.
            db.rollback()
            with env.sessions() as other:
                new_purchase = real_supersede(other, purchase_id)
                state["new_id"] = new_purchase.id
                other.commit()
        return real_backfill(db, purchase_id, session_id=session_id,
                             price_id=price_id)

    monkeypatch.setattr(
        pb, "backfill_product_purchase_session", _wrapped)
    return state


# ---------------------------------------------------------------------------
# T17: normal path — A's backfill loses to B's committed supersede;
# A must NOT return the original URL as created (generic 503)
# ---------------------------------------------------------------------------

def test_t17_normal_path_lost_backfill_no_dead_url(p164_env, monkeypatch):
    from app import models
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    captured = S._stripe_post_poisoned(monkeypatch, poisoned_keys=set())
    state = _inject_supersede_before_backfill(monkeypatch, p164_env)
    r = A._checkout(p164_env, rid, csrf)
    assert state["done"]  # the interleaving really was injected
    assert state["target"] == pid
    # Generic CheckoutError -> 503; the dead session's URL (cs_new_1,
    # created at Stripe for the old row) appears nowhere.
    assert r.status_code == 503, r.text[:300]
    assert "cs_new_1" not in r.text
    # Exactly one Stripe create (A's); B created no session.
    assert [c["key"] for c in captured] == [S._key(pid)]
    rows = S._rows(p164_env, user_id)
    assert len(rows) == 2
    by_id = {str(i): (s, sid) for i, s, sid in rows}
    # Old row stays failed with NO session id (T15 state preserved);
    # B's replacement is the live pending row, still session-less.
    assert by_id[str(pid)] == ("failed", None)
    assert by_id[str(state["new_id"])] == ("pending", None)
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0


# ---------------------------------------------------------------------------
# T18: supersede-retry path — the replacement row's backfill loses
# to a further supersede; the retry must not expose its URL
# ---------------------------------------------------------------------------

def test_t18_supersede_retry_lost_backfill_no_dead_url(p164_env, monkeypatch):
    from app import models
    _, user_id, csrf = A._make_user(p164_env)
    rid = A._source(p164_env, user_id)
    pid = A._seed_purchase(p164_env, user_id, rid, status="pending",
                           session_id=None)
    captured = S._stripe_post_poisoned(
        monkeypatch, poisoned_keys={S._key(pid)})
    state = _inject_supersede_before_backfill(monkeypatch, p164_env)
    r = A._checkout(p164_env, rid, csrf)
    assert state["done"]
    # The first (and only) backfill in this flow is the replacement
    # row's — the injection superseded THAT row before its backfill.
    new_id = state["target"]
    assert new_id != pid
    assert r.status_code == 503, r.text[:300]
    assert "cs_new_1" not in r.text  # replacement session's URL hidden
    # Exactly two Stripe creates: the poisoned original + the retry
    # under the replacement row's key. No third create.
    assert [c["key"] for c in captured] == [S._key(pid), S._key(new_id)]
    rows = S._rows(p164_env, user_id)
    assert len(rows) == 3
    by_id = {str(i): (s, sid) for i, s, sid in rows}
    assert by_id[str(pid)] == ("failed", None)       # first supersede
    assert by_id[str(new_id)] == ("failed", None)    # retry row superseded
    assert by_id[str(state["new_id"])] == ("pending", None)  # live row
    with p164_env.sessions() as db:
        assert db.query(models.Entitlement).count() == 0


# ---------------------------------------------------------------------------
# T19: already_complete on BOTH routes — navigable purchase-bound
# landing + runtime/DOM handling in BOTH paid_consent handlers
# ---------------------------------------------------------------------------

_NODE_HARNESS = r"""
'use strict';
const DATA = __DATA__;
class El {
  constructor(tag) {
    this.tagName = tag || ''; this.id = ''; this.style = {};
    this.textContent = ''; this.value = ''; this.listeners = {};
  }
  addEventListener(ev, fn) {
    (this.listeners[ev] = this.listeners[ev] || []).push(fn);
  }
}
const form = new El('form');
const errorEl = new El('p');
let payload = null;
globalThis.window = globalThis;
globalThis.document = {
  getElementById: function (id) {
    if (id === 'product-checkout-form') return form;
    if (id === 'product-checkout-error') return errorEl;
    return null;
  },
};
globalThis.FormData = class { constructor(f) {} };
globalThis.fetch = function () {
  return Promise.resolve({
    ok: true,
    json: function () { return Promise.resolve(payload); },
  });
};
async function flush() {
  for (let i = 0; i < 10; i++) {
    await new Promise(function (r) { setTimeout(r, 0); });
  }
}
(async () => {
  const out = [];
  for (let s = 0; s < DATA.scripts.length; s++) {
    for (const kase of DATA.cases) {
      form.listeners = {};
      errorEl.textContent = '';
      globalThis.location = { href: 'about:blank' };
      payload = kase.payload;
      eval(DATA.scripts[s]);
      const handlers = form.listeners.submit || [];
      if (handlers.length !== 1) {
        out.push({script: s, name: kase.name,
                  error: 'handlers=' + handlers.length});
        continue;
      }
      await handlers[0]({preventDefault: function () {}, target: form});
      await flush();
      out.push({
        script: s, name: kase.name,
        location: (typeof globalThis.location === 'string')
          ? globalThis.location
          : String(globalThis.location && globalThis.location.href),
        errorText: errorEl.textContent,
      });
    }
  }
  console.log('RESULT:' + JSON.stringify(out));
})().catch(function (e) {
  console.error(e && e.stack || e); process.exit(3);
});
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node required")
def test_t19_already_complete_both_routes_navigable_landing(
        p164b_env, monkeypatch):
    env = p164b_env
    _, user_id, csrf = B._make_user(env)
    # --- Investigation Report route -------------------------------------
    rid = A._source(env, user_id)
    pid = A._seed_purchase(env, user_id, rid, status="pending",
                           session_id="cs_done_ir")
    S._stripe_post_poisoned(monkeypatch, poisoned_keys={S._key(pid)})
    S._stripe_get_sessions(monkeypatch, {
        "cs_done_ir": {"id": "cs_done_ir", "status": "complete",
                       "url": None, "payment_status": "paid"}})
    r = A._checkout(env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    ir_payload = r.json()
    assert ir_payload["purchase_id"] == str(pid)
    assert ir_payload["session_status"] == "complete"
    ir_landing = ir_payload["checkout_url"]
    # Navigable (not the complete session's null url) and bound to
    # THIS purchase on the settlement-aware report return surface.
    assert ir_landing
    assert f"/reports/{rid}" in ir_landing
    assert "checkout=success" in ir_landing
    assert f"purchase={pid}" in ir_landing
    assert ir_payload["return_url"] == ir_landing
    # Row untouched: still pending, still carrying its session id.
    assert S._rows(env, user_id) == [(pid, "pending", "cs_done_ir")]

    # --- Digest (compare) route ------------------------------------------
    digest = hashlib.sha256(b"t19-compare-content").hexdigest()
    pid_d = S._seed_digest_purchase(env, user_id, "compare", digest,
                                    session_id="cs_done_digest")
    S._stripe_post_poisoned(monkeypatch, poisoned_keys={S._key(pid_d)})
    S._stripe_get_sessions(monkeypatch, {
        "cs_done_digest": {"id": "cs_done_digest", "status": "complete",
                           "url": None, "payment_status": "paid"}})
    r2 = B._checkout(env, csrf, "compare", digest)
    assert r2.status_code == 200, r2.text[:300]
    digest_payload = r2.json()
    assert digest_payload["purchase_id"] == str(pid_d)
    assert digest_payload["session_status"] == "complete"
    digest_landing = digest_payload["checkout_url"]
    assert digest_landing
    assert "/products/return" in digest_landing
    assert "product_checkout=success" in digest_landing
    assert "sku=compare" in digest_landing
    assert f"purchase={pid_d}" in digest_landing
    assert digest_payload["return_url"] == digest_landing

    # --- Runtime/DOM: BOTH paid_consent checkout handlers ----------------
    # Execute each handler script in Node against each route's real
    # already_complete payload: session_status "complete" must
    # navigate to that payload's landing and must NOT display
    # "Checkout is unavailable right now." (or any error text).
    template = (Path(__file__).resolve().parent.parent / "app"
                / "templates" / "paid_consent.html").read_text()
    scripts = [s for s in re.findall(r"<script>(.*?)</script>",
                                     template, re.S)
               if "product-checkout-form" in s]
    assert len(scripts) == 2  # BOTH handlers are exercised
    data = {"scripts": scripts, "cases": [
        {"name": "ir", "payload": ir_payload},
        {"name": "digest", "payload": digest_payload}]}
    node_src = _NODE_HARNESS.replace(
        "__DATA__", json.dumps(data))
    proc = subprocess.run(["node", "-e", node_src],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, \
        f"node harness failed:\n{proc.stdout}\n{proc.stderr}"
    line = next(l for l in proc.stdout.splitlines()
                if l.startswith("RESULT:"))
    out = json.loads(line[len("RESULT:"):])
    assert len(out) == 4  # 2 handlers x 2 route payloads
    expected = {"ir": ir_landing, "digest": digest_landing}
    for entry in out:
        assert entry["location"] == expected[entry["name"]], entry
        assert entry["errorText"] == "", entry
        assert "Checkout is unavailable" not in entry["errorText"]


# ---------------------------------------------------------------------------
# T20: positive control — the normal created flow on BOTH routes
# still returns the URL and the row carries the session id (guard
# against J1 over-blocking; passes on both trees, the T16 pattern)
# ---------------------------------------------------------------------------

def test_t20_normal_created_flow_still_returns_url_and_backfills(
        p164b_env, monkeypatch):
    env = p164b_env
    _, user_id, csrf = B._make_user(env)
    captured = S._stripe_post_poisoned(monkeypatch, poisoned_keys=set())
    # Investigation Report route, fresh purchase.
    rid = A._source(env, user_id)
    r = A._checkout(env, rid, csrf)
    assert r.status_code == 200, r.text[:300]
    ir_id = r.json()["purchase_id"]
    assert r.json()["checkout_url"] == \
        "https://checkout.stripe.com/pay/cs_new_1"
    # Digest route, fresh purchase.
    digest = hashlib.sha256(b"t20-compare-content").hexdigest()
    r2 = B._checkout(env, csrf, "compare", digest)
    assert r2.status_code == 200, r2.text[:300]
    digest_id = r2.json()["purchase_id"]
    assert r2.json()["checkout_url"] == \
        "https://checkout.stripe.com/pay/cs_new_2"
    assert [c["key"] for c in captured] == \
        [S._key(ir_id), S._key(digest_id)]
    by_id = {str(i): (s, sid) for i, s, sid in S._rows(env, user_id)}
    # Each row is pending AND carries the session id its returned
    # URL points at — J1's positive side.
    assert by_id[ir_id] == ("pending", "cs_new_1")
    assert by_id[digest_id] == ("pending", "cs_new_2")
