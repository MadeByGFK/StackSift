# StackSift

Turn noisy application logs into a quick, readable incident summary.

**🌐 Try it in your browser — free, no signup:**
**https://stacksift.goodfolkdigital.com**

Drop in a `.log` file and get severity counts, recurring issues ranked by
severity and frequency, a health verdict, and the #1 thing to investigate
first. Your file is processed using temporary storage and cleaned up when
analysis finishes — no upload archive, and uploads are never used for
training. (The framework may briefly spool the raw upload to disk before
redaction; operational request logs are recorded. See Privacy below.)

Prefer the terminal? StackSift is also a Python CLI (see below).

## Why StackSift?

Log files are useful, but manually scanning hundreds or thousands of lines is
slow and repetitive. StackSift gives you a fast first pass so you can answer
questions like:

- How many warnings, errors, and critical events occurred?
- Which issues appeared most often?
- What should I investigate first?

It's the first five minutes of an incident, automated — built by a production
support analyst who triages 120+ incidents a month.

## Web version

The hosted version lives at
[stacksift.goodfolkdigital.com](https://stacksift.goodfolkdigital.com):

- Drag-and-drop upload (`.log` / `.txt`, up to 10 MB)
- Plain-text logs plus auto-detected **JSON-lines**
- Beautiful HTML incident report, or download a `.txt` summary
- Free tier: 10 analyses/hour, no account needed
- Private by design: uploads use temporary storage and are cleaned up after
  processing — see the [privacy model](src/web/README.md#privacy-model)

The web app is a thin FastAPI wrapper around the analyzer in this repo. Want
to host your own? See `src/web/README.md`.

## CLI

### Installation

```
git clone https://github.com/MadeByGFK/StackSift.git
cd StackSift
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

On Windows PowerShell, activate the environment with:

```
.venv\Scripts\Activate.ps1
```

### Usage

Analyze one log file:

```
stacksift analyze sample_logs/app.log
```

Analyze every supported log file in a folder:

```
stacksift analyze sample_logs
```

StackSift prints the summary to the terminal and saves a text report.

### Example Output

```
StackSift Summary
File: sample_logs
Total lines: 10
Parsed lines: 9
Malformed lines: 1
Scan time: 0.003s
Files scanned: 2

Log Levels
INFO       3
WARN       2
ERROR      3
CRITICAL   1

Issues
ERROR      Database connection failed   3
WARN       Request timed out            2

Report saved to: reports/sample_logs_report.txt
```

The exact issue text, counts, scanned files, and report path depend on the
analyzed input.

### Expected Log Format

StackSift reads simple application logs containing recognizable severity
labels such as:

```
2026-07-31 09:15:02 INFO Application started
2026-07-31 09:15:10 WARN Response time exceeded threshold
2026-07-31 09:15:22 ERROR Database connection failed
2026-07-31 09:15:24 CRITICAL Service unavailable
```

The web version additionally auto-detects JSON-lines
(`{"timestamp": "...", "level": "error", "message": "..."}`). Malformed or
unsupported lines are counted separately rather than silently dropped.

## Privacy

- The web version processes uploads using temporary storage and cleans it
  up when analysis finishes. Recognized secret patterns are redacted before
  the analysis temp file is created; that file is deleted in a `finally`
  block during normal processing. The framework may spool the raw upload
  to disk before redaction, and abrupt termination can interrupt cleanup —
  this is not a secure-erasure guarantee. Redaction is best effort and can
  miss secrets.
- We keep no upload archive and do not use uploads for training. (This
  describes current behavior — durable results storage for account holders
  is planned for a future release.) Operational request logs are recorded.
- Analysis works anonymously — no account required for the free tier.
  Optional accounts (email/password, Google, GitHub) use a session cookie
  to keep you signed in.
- The CLI runs entirely on your machine — your logs never leave it.

## Tech Stack

- Python 3.10+
- Typer, Rich, pytest, setuptools
- Web: FastAPI + Jinja2 (see `src/web/`)

## Roadmap

- Native multi-format parsing (JSON-lines, multiline stack traces) in the core library
- CSV and HTML exports from the CLI
- Error-spike detection
- AI "likely root cause" summaries (web, premium tier)

## Status

StackSift is an early-stage project, released as **v0.1.0**. File and folder
analysis are working; richer reporting and operational insights are under
active development.

## Author

Built by K as a practical developer tool for faster log triage and
operational troubleshooting.
