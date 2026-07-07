# StackSift

StackSift is a Python CLI tool that scans log files, counts severity levels, and summarizes recurring issues.

## Features

- Parse simple application log files
- Count INFO, WARN, ERROR, and CRITICAL entries
- Identify repeated error messages
- Print a clean terminal summary
- Export a text report

## Example

```bash
stacksift sample_logs/app.log
```

## Sample Output

```txt
StackSift Summary

File: sample_logs/app.log
Total lines: 10
Parsed lines: 10

INFO: 3
WARN: 2
ERROR: 4
CRITICAL: 1
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run Tests

```bash
pytest
```

## Roadmap

- HTML reports
- CSV export
- Folder scanning
- Error spike detection
- Pattern detection