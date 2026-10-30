"""Checkout error-body logging (issue #68 follow-up from the 2026-10-23 E2E).

The staging end-to-end hit a Stripe HTTP 400 whose error body never reached
our logs — the server logged the status only, so diagnosis needed dashboard
spelunking. create_checkout_session now logs Stripe's structured error
fields (type/code/param/message) for failed calls, never the raw body, and
redacts email-looking values from the message.

Stripe's HTTP API is faked at the httpx boundary — no network, no keys.
"""
import logging

import pytest


class _FakeStripeResponse:
    def __init__(self, status_code=400, payload=None, json_raises=False):
        self.status_code = status_code
        self._payload = payload
        self._json_raises = json_raises

    def json(self):
        if self._json_raises:
            raise ValueError("no JSON here")
        return self._payload


@pytest.fixture
def logging_env(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_cycle_fixture")
    monkeypatch.setenv("STRIPE_PRICE_STARTER", "price_test_starter")


def _call(monkeypatch, resp):
    from app import stripe_billing

    monkeypatch.setattr(stripe_billing.httpx, "post", lambda *a, **k: resp)
    with pytest.raises(stripe_billing.CheckoutError):
        stripe_billing.create_checkout_session(
            user_id="u1", pack_id="starter", purchase_id="p1",
            success_url="https://x/s", cancel_url="https://x/c")


def test_400_logs_stripe_error_fields(logging_env, monkeypatch, caplog):
    resp = _FakeStripeResponse(status_code=400, payload={
        "error": {
            "type": "invalid_request_error",
            "code": "resource_missing",
            "message": "No such price: 'price_test_starter'",
            "param": "line_items[0][price]",
        }
    })
    with caplog.at_level(logging.ERROR, logger="app.stripe_billing"):
        _call(monkeypatch, resp)
    record = next(r for r in caplog.records if "Stripe checkout returned HTTP 400" in r.message)
    assert "type=invalid_request_error" in record.message
    assert "code=resource_missing" in record.message
    assert "param=line_items[0][price]" in record.message
    assert "No such price" in record.message


def test_email_redacted_from_logged_message(logging_env, monkeypatch, caplog):
    resp = _FakeStripeResponse(status_code=400, payload={
        "error": {
            "type": "invalid_request_error",
            "message": "Invalid email address: buyer@example.com",
        }
    })
    with caplog.at_level(logging.ERROR, logger="app.stripe_billing"):
        _call(monkeypatch, resp)
    record = next(r for r in caplog.records if "Stripe checkout returned HTTP 400" in r.message)
    assert "buyer@example.com" not in record.message
    assert "[redacted-email]" in record.message


def test_non_json_body_falls_back(logging_env, monkeypatch, caplog):
    resp = _FakeStripeResponse(status_code=500, payload=None, json_raises=True)
    with caplog.at_level(logging.ERROR, logger="app.stripe_billing"):
        _call(monkeypatch, resp)
    record = next(r for r in caplog.records if "Stripe checkout returned HTTP 500" in r.message)
    assert "unparseable-body" in record.message


def test_empty_error_object_falls_back(logging_env, monkeypatch, caplog):
    resp = _FakeStripeResponse(status_code=400, payload={"error": {}})
    with caplog.at_level(logging.ERROR, logger="app.stripe_billing"):
        _call(monkeypatch, resp)
    record = next(r for r in caplog.records if "Stripe checkout returned HTTP 400" in r.message)
    assert "empty-error" in record.message


def test_error_detail_unit_cases():
    from app import stripe_billing

    assert stripe_billing._stripe_error_detail(_FakeStripeResponse(
        payload={"error": {"type": "api_error", "message": "boom"}})) == \
        "type=api_error message=boom"
    assert stripe_billing._stripe_error_detail(_FakeStripeResponse(
        payload={"ok": True})) == "unparseable-body"
    assert stripe_billing._stripe_error_detail(_FakeStripeResponse(
        payload=None, json_raises=True)) == "unparseable-body"
