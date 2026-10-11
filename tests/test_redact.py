from stacksift.redact import redact_secrets, REDACTED


def test_aws_access_key():
    assert redact_secrets("key AKIAIOSFODNN7EXAMPLE here") == f"key {REDACTED} here"


def test_github_token():
    token = "ghp_" + "a" * 36
    assert redact_secrets(f"token {token} leaked") == f"token {REDACTED} leaked"


def test_stripe_key():
    # key assembled at runtime so secret scanners don't flag the test file
    key = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
    out = redact_secrets(f"stripe_key={key}")
    assert key not in out
    assert out == "stripe_key=[REDACTED]"


def test_labeled_api_key_keeps_label():
    out = redact_secrets("calling with api_key=abc123xyz789def456")
    assert out == f"calling with api_key={REDACTED}"


def test_password_redacted():
    out = redact_secrets('login failed password="hunter2" for user bob')
    assert "hunter2" not in out
    assert REDACTED in out


def test_bearer_token():
    out = redact_secrets("auth: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
    assert "eyJhbGci" not in out
    assert f"Bearer {REDACTED}" in out


def test_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    assert redact_secrets(f"cert {pem} end") == f"cert {REDACTED} end"


def test_clean_text_untouched():
    text = "2026-10-11 08:00:01 INFO order #88412 completed in 212ms"
    assert redact_secrets(text) == text


def test_labeled_secret_in_parens_keeps_paren():
    out = redact_secrets("loaded config (api_key=demo_7f3a9c2e8b1d4f6a5c3e)")
    assert out == "loaded config (api_key=[REDACTED])"
