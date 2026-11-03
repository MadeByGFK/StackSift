"""Issue #130: after a successful password reset, confirm and route to login.

Founder report 2026-11-03: submitting a new password from the emailed
reset link left the user sitting on the reset screen — the server's JSON
message was written into the form's status line and nothing moved. Now:

- The reset form opts into a confirmation modal via
  data-success-modal="You have changed your password" +
  data-success-url="/login" (the same opt-in attribute style as
  data-notify-feedback / data-checkout-form / data-success-url).
- On a successful submit the shared handler shows the modal instead of
  the inline status text; acknowledging it (OK — and, since the change
  has already completed server-side, Escape / overlay click too)
  navigates to the login page.
- No server change: /auth/reset keeps its exact JSON contract and the
  reset-token mechanics (single-use, expiry, invalidation) are untouched.
  Errors still land in the status element; other forms (login/logout)
  keep their immediate data-success-url redirect.

The JS behavior is asserted as a static contract over the shared script
(the pattern used by test_issue68_modal_quickbuy), the reset page HTML
is asserted as rendered, and the endpoint contract is exercised for real.
"""
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"
SCRIPT = (TEMPLATES / "auth_form_script.html").read_text()
RESET_PAGE = (TEMPLATES / "reset.html").read_text()
LOGIN_PAGE = (TEMPLATES / "login.html").read_text()

REQUIRED_MESSAGE = "You have changed your password"


def _form_tag(page_html: str, action: str) -> str:
    for line in page_html.splitlines():
        if "<form" in line and f'action="{action}"' in line:
            return line
    raise AssertionError(f"no form with action={action} found")


def test_reset_form_opts_into_success_modal_to_login():
    tag = _form_tag(RESET_PAGE, "/auth/reset")
    assert f'data-success-modal="{REQUIRED_MESSAGE}"' in tag
    assert 'data-success-url="/login"' in tag


def test_handler_shows_modal_only_for_opted_in_forms():
    # The modal branch is gated on the opt-in attribute and a successful
    # response, and replaces the inline status text for that form only.
    assert "form.hasAttribute('data-success-modal')" in SCRIPT
    assert "const successModal = response.ok && form.hasAttribute('data-success-modal');" in SCRIPT
    assert "if (output && !successModal)" in SCRIPT
    assert "showSuccessModal(form.dataset.successModal, form.dataset.successUrl);" in SCRIPT
    # The pre-existing immediate redirect remains for plain success-url forms.
    assert "} else if (response.ok && form.dataset.successUrl) location.assign(form.dataset.successUrl);" in SCRIPT


def test_success_modal_acknowledgement_navigates():
    assert "function showSuccessModal(message, url)" in SCRIPT
    assert "overlay.id = 'success-modal';" in SCRIPT
    assert "msg.textContent = message;" in SCRIPT
    assert "ok.textContent = 'OK';" in SCRIPT
    # Acknowledgement closes the modal and hands off to the target URL.
    assert "if (url) location.assign(url);" in SCRIPT
    assert "ok.addEventListener('click', acknowledge);" in SCRIPT


def test_other_auth_forms_keep_immediate_redirect():
    # Login (and the logout forms) must NOT gain the modal: their
    # data-success-url immediate redirect is the established behavior.
    assert 'data-success-modal' not in _form_tag(LOGIN_PAGE, "/auth/login")
    assert 'data-success-url="/"' in _form_tag(LOGIN_PAGE, "/auth/login")


def test_rendered_reset_page_carries_the_modal_contract(auth_env):
    resp = auth_env.client.get("/reset?token=test-token")
    assert resp.status_code == 200
    tag = _form_tag(resp.text, "/auth/reset")
    assert f'data-success-modal="{REQUIRED_MESSAGE}"' in tag
    assert 'data-success-url="/login"' in tag


def test_reset_endpoint_contract_unchanged(auth_env):
    # Failure path stays a JSON error (no modal state to acknowledge).
    resp = auth_env.client.post(
        "/auth/reset",
        data={"token": "bad-token", "new_password": "NewSecurePass456!"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "Invalid or expired reset link."
