# StackSift Web

The hosted front end for [StackSift](https://github.com/MadeByGFK/StackSift).

**Live:** https://stacksift.goodfolkdigital.com

Drop in a log file, get an incident summary — severity counts, recurring
issues ranked by severity, a health verdict, and the #1 thing to investigate
first. Free, no signup, nothing stored.

## Features

- Drag-and-drop upload (`.log` / `.txt`, up to 10 MB)
- Plain-text logs plus auto-detected **JSON-lines** (converted on the fly)
- HTML incident report in the browser, or download a `.txt` summary
- Free tier: 10 analyses/hour per IP (in-memory limiter, no accounts yet)
- Private by design: uploads are analyzed in memory and deleted immediately

## Run locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
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

`requirements.txt` installs the StackSift analyzer straight from GitHub, so
the web app always tracks the library.

## Privacy model

Uploads are written to a temp file, analyzed, and deleted in a `finally`
block. Contents are never logged, stored, or persisted. Reports are rendered
per-request — there are no share links because there is nothing stored to
link to.

## Roadmap

- Magic-link auth + credits ledger (same credits model as Rilivery)
- Stripe payment-link top-ups
- Native multi-format parsing in the core library (replaces the JSONL adapter)
- AI "likely root cause" summaries as a premium tier
