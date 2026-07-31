# StackSift

StackSift is a Python command-line tool that turns noisy application logs into a quick, readable summary.

It scans a log file, counts severity levels, surfaces recurring issues, prints the results in clean terminal tables, and saves a text report for later review.

## Why StackSift?

Log files are useful, but manually scanning hundreds or thousands of lines is slow and repetitive. StackSift provides a fast first pass so you can answer questions like:

- How many warnings, errors, and critical events occurred?
- Which issues appeared most often?
- Was the file parsed successfully?
- What should I investigate first?

## Current Features

- Analyze a single application log file
- Count `INFO`, `WARN`, `ERROR`, and `CRITICAL` entries
- Identify repeated issue messages
- Display results with Rich terminal tables
- Save a plain-text analysis report
- Install as a local `stacksift` CLI command
- Run automated tests with pytest

## Tech Stack

- Python 3.10+
- Typer
- Rich
- pytest
- setuptools

## Installation

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/GFKolby/StackSift.git
cd StackSift

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Usage

Analyze a log file:

```bash
stacksift analyze sample_logs/app.log
```

StackSift prints the summary to the terminal and saves a text report.

## Example Output

```text
StackSift Summary

File: sample_logs/app.log
Total lines: 10
Parsed lines: 10

Log Levels
INFO       3
WARN       2
ERROR      4
CRITICAL   1

Top Issues
Database connection failed   3
Request timed out            2

Report saved to: reports/app_report.txt
```

The exact issue text and report path depend on the analyzed file.

## Expected Log Format

StackSift is currently designed for simple application logs containing recognizable severity labels such as:

```text
2026-07-31 09:15:02 INFO Application started
2026-07-31 09:15:10 WARN Response time exceeded threshold
2026-07-31 09:15:22 ERROR Database connection failed
2026-07-31 09:15:24 CRITICAL Service unavailable
```

Malformed or unsupported lines may not be included in the parsed-line count.

## Development

Run the test suite:

```bash
pytest
```

Run the CLI without installing the command globally:

```bash
python -m stacksift.cli analyze sample_logs/app.log
```

## Project Structure

```text
StackSift/
├── src/
│   └── stacksift/
│       ├── analyzer.py
│       └── cli.py
├── tests/
├── sample_logs/
├── pyproject.toml
└── README.md
```

## Roadmap

Planned improvements include:

- Folder and multi-file scanning
- CSV and HTML exports
- Error-spike detection
- More flexible parsing patterns
- Trend and health insights
- Configurable report output

## Status

StackSift is an early-stage project currently released as **v0.1.0**. The core analysis workflow works, while additional parsing, reporting, and multi-file features are still being developed.

## Author

Built by [Kolby Kinsey](https://github.com/GFKolby) as a practical developer tool for faster log triage and operational troubleshooting.
