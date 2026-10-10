# StackSift

Turn noisy application logs into a quick, readable incident summary.

**🌐 Try it in your browser — free, no signup:**
**https://stacksift.goodfolkdigital.com**

Drop in a `.log` file and get severity counts, recurring issues ranked by
severity and frequency, a health verdict, and the #1 thing to investigate
first. Your file is analyzed in memory and deleted immediately — nothing is
ever stored.

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
- Private by design: files are processed in memory and deleted on the spot

The web app is a thin FastAPI wrapper around the analyzer in this repo. Want
to host your own? See `web/README.md`.

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

- The web version analyzes uploads in memory and deletes them immediately.
  Nothing is stored, logged, or used to train anything.
- The CLI runs entirely on your machine — your logs never leave it.

## Tech Stack

- Python 3.10+
- Typer, Rich, pytest, setuptools
- Web: FastAPI + Jinja2 (see `web/`)

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

Built by GFK as a practical developer tool for faster log triage and
operational troubleshooting.
