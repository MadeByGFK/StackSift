# Accounts security and verification

PR #12 remains scoped to accounts. This remediation addresses review
5512054463 on original head `0f725a8a92b2187b692d062339849295d949e446`.
It does not authorize merging or deployment.

## Findings and corrections

| Finding | Root cause and correction |
| --- | --- |
| UUID collection failure | `GUID.load_dialect_impl` returned compiled SQL strings. It now returns dialect type descriptors, normalizes UUID bindings, and round-trips UUID values on SQLite and PostgreSQL. |
| OAuth email collision | New identities unconditionally inserted a unique email. Both providers now reject collisions with a sign-in/settings linking path. Database uniqueness races roll back safely. Matching email never links, overwrites, or duplicates a user. |
| OAuth state and linking | Browser cookies previously selected action and held all state authority. `oauth_states` stores hashed state and browser binding, provider, action, initiating session, expiry, and use time. An atomic claim consumes state before the exchange, including failed attempts. Linking requires authenticated CSRF-protected POST; callbacks recheck the same live session after network I/O and lock it before linking. Login state cannot become a linking request. |
| Provider verification | Google ID tokens require RS256 signature, trusted fixed JWKS endpoint, issuer, audience/authorized party, expiry, issued-at, subject, nonce, and boolean verified email. GitHub requires a positive integer identity and boolean primary/verified email. Malformed responses fail closed. |
| Test isolation | Removed module-import environment changes, shared in-memory database, and permanent dependency overrides. Each account test gets a temporary database and scoped overrides, clients, limiter and mail/provider mocks. |
| PostgreSQL migration mismatch | The initial account migration now uses PostgreSQL UUID with SQLite VARCHAR(36); the next revision adds OAuth state. Tests perform upgrade, schema/model comparison, UUID round-trip, uniqueness/FK enforcement, downgrade, and re-upgrade on an actual PostgreSQL server. |
| Enumeration | New, unverified-existing, and verified-existing signups return identical HTTP 200/body and perform bcrypt work. Mail runs after response delivery. Missing/OAuth-only login paths perform dummy bcrypt verification and share the invalid-credentials response. Forgot-password responses are generic. Verification/reset failures do not identify an email. A correct password may receive the verification-required message. |
| Token races | Verification/reset tokens are hashed, expiring and atomically claimed. A user-row write lock serializes sibling-token redemption; sibling invalidation and password/session changes commit in the same transaction. Reset revokes all sessions. Verification GET is non-consuming; explicit POST confirms the email. |
| Browser integration | Actual signup/login/forgot/reset/verify forms submit CSRF tokens and render safe text errors. Settings links providers by native POST and supports CSRF logout/revocation. Sessions use Secure, HttpOnly, SameSite=Lax, host-only cookies and rotate on password login. Account pages use no-store and no-referrer. |
| Related account defects | Fixed verification/reset email URLs, removed token-bearing development email logs, report missing delivery configuration as failure, and enforce bcrypt's 72-byte input limit. |

## Test commands

Install development dependencies and the browser:

```sh
python -m pip install -e '.[dev]' -r requirements-dev.txt
python -m playwright install --with-deps chromium
```

Use a disposable PostgreSQL database whose user can create/drop schemas.
Every PostgreSQL test creates and removes its own randomly named schema;
`DATABASE_URL` and application data are not changed. Do not use production.

```sh
export TEST_POSTGRES_URL='postgresql+psycopg2://stacksift_test:local_test_only@localhost:5432/stacksift_test'
export RUN_AUTH_BROWSER=1
python -m pytest tests/ src/web/tests/ -q
```

Repeat with reversed collection order:

```sh
python - <<'PY'
import pytest
class ReverseOrder:
    def pytest_collection_modifyitems(self, items):
        items.reverse()
raise SystemExit(pytest.main(['tests/', 'src/web/tests/', '-q'], plugins=[ReverseOrder()]))
PY
```

CI provisions PostgreSQL 16 and Chromium and enables both integration suites.
Without their explicit environment flags, local runs skip those suites; such
runs must not be described as PostgreSQL/browser verification.

Local verification used Python 3.13, PostgreSQL 16.2, and Chromium. Normal and
reversed full-suite runs passed **278 tests plus 12 subtests**. The only warning
was Starlette's deprecation of its httpx-based test transport. PostgreSQL
migration/schema tests and same-token/different-sibling concurrent redemption
checks passed for both verification and reset. The HTTPS browser test exercises
signup, verify, login errors/success, both provider-link forms, secure cookies,
logout, forgot and reset; provider authorization/exchange and email delivery
are explicitly mocked.

## Frozen diagnostic comparison

The original six-fixture archive is external to this repository. Verify its
manifest checksums and compare all analysis output against the original PR head:

```sh
mkdir -p /tmp/stacksift-accounts-baseline
git archive 0f725a8a92b2187b692d062339849295d949e446 src/web/app | tar -x -C /tmp/stacksift-accounts-baseline
python tools/compare_frozen_diagnostics.py \
  --fixtures /path/to/stacksift_six_benchmark_regression_fixtures.zip \
  --baseline /tmp/stacksift-accounts-baseline/src/web
```

**6/6 identical outputs**, after excluding only elapsed time and the random
analysis temporary filename. The archive's manifest checksums were verified.
Health labels remained:

- Ecommerce and authentication incidents: Elevated Incident Activity.
- Memory, network, and mixed-format incidents: Critical.
- Healthy application: No Escalation Detected.

No diagnostic engine, vendored parser/ranker, upload limit, analysis route,
benchmark fixture, or pre-accounts regression test was changed by this remediation.

## Deployment prerequisites and remaining limits

- Live Google/GitHub account authorization and Resend delivery have **not** been
  tested. They still require configured credentials and separately authorized
  staging smoke tests. A passing mocked test is not live-provider evidence.
- `APP_URL` must be the correct HTTPS origin and registered provider callback
  URLs must match it. Secure host-prefixed cookies intentionally require HTTPS,
  including local manual testing. Existing pre-remediation session-cookie names
  are not accepted.
- The corrected initial migration is for the unreleased accounts schema. If an
  environment already applied the original VARCHAR-based PostgreSQL revision,
  do not simply stamp it as current: it needs an independently reviewed data
  conversion migration before use. This task did not change a deployed database.
- Rate limiting remains per-process/in-memory. Multi-worker scaling requires
  shared rate limiting; restarts reset counters. HIBP availability still fails
  open by design. Background email delivery has no durable retry queue.
- Auth code does not log raw tokens. Hosting/access logs must also avoid retaining
  verification/reset query strings. Account responses suppress referrers, but
  that cannot configure an external proxy's logging policy.
- The existing homepage has a console error because its head script accesses
  `upload-form` before the form exists. This is present in the original head and
  outside accounts scope; it was not changed. The browser test permits only
  that exact homepage error and rejects errors on every account page.

Status: **READY FOR INDEPENDENT REVIEW**, subject to the live integration and
operational checks above before any separately authorized deployment.
