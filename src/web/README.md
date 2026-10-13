# StackSift Web

The hosted front end for [StackSift](https://github.com/MadeByGFK/StackSift).

**Live:** https://stacksift.goodfolkdigital.com

Drop in a log file, get an incident summary — severity counts, recurring
issues ranked by severity, a health verdict, and the #1 thing to investigate
first. Free, no signup, no upload archive.

## Features

- Drag-and-drop upload (`.log` / `.txt`, up to 10 MB)
- Plain-text logs plus auto-detected **JSON-lines** (converted on the fly)
- HTML incident report in the browser, or download a `.txt` summary
- Free tier: 10 analyses/hour per IP (in-memory limiter, no accounts yet)
- Private by design: temporary uploads with best-effort secret redaction

## Run locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --no-proxy-headers
```

Open http://localhost:8000 and try the sample logs in the
[StackSift repo](https://github.com/MadeByGFK/StackSift/tree/master/sample_logs).

## Deploy your own

The app is built for [Railway](https://railway.app) but runs anywhere
Python does:

1. Push this folder as a repo (or as `web/` in the StackSift repo — set
   Railway's root directory accordingly).
2. New Project → Deploy from GitHub. Railway auto-detects the `Procfile`
   and `requirements.txt`; no extra build config needed.
3. The app reads `$PORT`, and `/health` is the health-check endpoint.
4. For a custom domain: add a CNAME to your Railway domain, then attach the
   domain in Railway.

## Project layout

```
app/
  main.py        # FastAPI app: routes, validation, rate limiting
  service.py     # upload analysis, JSON-lines adapter, report data
  rate_limit.py  # in-memory sliding-window limiter
  templates/     # landing page + report page (Jinja2)
  static/        # stylesheet
```

The diagnostic library is vendored in `app/vendor/`.

## Privacy model

Starlette's multipart parser uses a spooled temporary file. Larger uploads
can reach disk unredacted before the endpoint runs. The analysis service
redacts recognized patterns, writes a separate temporary analysis file, and
unlinks it in a finally block. The framework closes the upload spool during
request cleanup. Abrupt termination can interrupt cleanup; this is not a
secure-erasure guarantee. Redaction is best effort and can miss secrets.
Operational request logs remain enabled. No upload archive is maintained.

Disabling spooling alone would put larger uploads in RAM without solving
admission control. A memory-only guarantee requires bounded streaming input,
early size enforcement, concurrency limits, and an analyzer that accepts
in-memory input. This patch deliberately retains spooling and discloses it.

## Railway client identity

The Procfile explicitly selects `STACKSIFT_PROXY_MODE=railway` and disables
Uvicorn proxy-header rewriting. No CIDR variable is required on Railway:
`STACKSIFT_TRUSTED_PROXY_CIDRS` may be empty or unset.

Railway mode validates and canonicalizes the first X-Forwarded-For entry,
including IPv6 and IPv4-mapped IPv6. It does not scan for a later public IP.
Missing, duplicate or invalid headers return 503 on identity-dependent routes,
rather than falling back to shared proxy quota buckets. /health remains usable.
It ignores X-Real-IP because CDN routing can make that value a CDN address.

This is an explicit platform trust policy, not a generic proxy algorithm.
All public requests must enter through Railway HTTP ingress. Do not expose
this app via a TCP proxy or a direct public listener. Private-network workloads
must be trusted: their direct requests bypass edge header sanitization.
For another hosting setup, do not use this Procfile unchanged. The default
`cidr` mode retains the configured-peer X-Real-IP policy.

Sources checked during this correction:
- [Railway employee recommends first XFF and explains the CDN X-Real-IP bug](https://station.railway.com/questions/which-header-should-i-rely-on-for-real-c-d78a6f96)
- [Railway employee confirms edge overwrite and no direct public HTTP origin access](https://station.railway.com/questions/need-authoritative-railway-client-ip-p-b7a7b4bd)

Before production promotion, deploy to staging and verify ordinary requests,
forged XFF/X-Real-IP values, duplicate headers, the burst rejection sequence,
and separate client networks. Check the production custom-domain route as a
separate ingress path. Unit tests cannot prove edge sanitization.

## Reproducible validation

From the repository root:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
PYTHONPATH=src/web python -m app.smoke_test
```

The original full suite collected 80 tests: 79 passed and one failed.
`tests/test_insights 2.py` was a stale duplicate with four cases already
covered by `test_insights.py`; its old Healthy expectation contradicted the
current no-timeline contract. Removing that duplicate preserves the 76
current cases without ignoring failures or changing diagnostic behavior.
Additional web tests cover proxy trust, address parsing, HTTP quota accounting
and Retry-After. The previously reported six frozen benchmarks are not in
this repository; no benchmark pass claim is made here.

## Roadmap

- Magic-link auth + credits ledger (same credits model as Rilivery)
- Stripe payment-link top-ups
- Native multi-format parsing in the core library (replaces the JSONL adapter)
- AI "likely root cause" summaries as a premium tier
