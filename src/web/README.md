# StackSift Web

Free hosted log-file analyzer — the thin-slice web front end for
[StackSift](https://github.com/MadeByGFK/StackSift). Drop in a `.log` file,
get an incident summary. No accounts, no storage.

Live target: `https://stacksift.goodfolkdigital.com`

## What's here

- `app/main.py` — FastAPI app: upload page, `/analyze` endpoint, `/health` check
- `app/service.py` — upload handling: temp-file analysis (deleted immediately),
  JSON-lines auto-detection + conversion, HTML/text report data
- `app/rate_limit.py` — in-memory sliding-window limiter (10 analyses/hour/IP)
- `app/templates/` — landing page (`index.html`) and report page (`report.html`)
- `app/static/style.css` — dark theme

## Run locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000 and drop in `stacksift-lib/sample_logs/app.log`
(the sample logs are in the cloned library, gitignored here).

## Deploy to Railway

1. Push this folder as its own repo (or as `web/` in the StackSift repo —
   if so, point Railway's root directory at it).
2. New Project → Deploy from GitHub repo. Railway auto-detects the
   `Procfile` and `requirements.txt`. No build config needed.
3. The app reads `$PORT`, and `/health` is the health check endpoint.
4. In Cloudflare, add a CNAME for `stacksift` → your Railway domain
   (proxy on), then add the custom domain in Railway.

## Limits (free tier, tune with real usage)

- 10 MB max file, `.log` / `.txt` only
- 10 analyses per hour per IP (in-memory; fine on a single instance)

## Privacy model

Uploads are written to a temp file, analyzed, and deleted in a `finally`
block. Contents are never logged, stored, or persisted. The report page is
rendered per-request — there are no share links because there is nothing
stored to link to.

## Roadmap (post-validation)

- Magic-link auth + credits ledger (same credits model as Rilivery)
- Stripe payment-link top-ups
- Native multi-format parsing in the library (replaces the JSONL adapter here)
- AI "likely root cause" summary as a premium tier
