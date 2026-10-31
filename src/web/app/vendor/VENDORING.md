# Vendored StackSift Library

## Why vendoring?

Railway's pip cache has twice served stale versions of the `stacksift`
package despite immutable commit pins in requirements.txt:
1. `redact.py` — new module not picked up (fixed by vendoring to `app/redact.py`)
2. Phase D — new functions not picked up (caused production 500s)

Vendoring eliminates the pip-cache dependency entirely. What is pushed
to git is what runs on Railway. No hidden version mismatches.

## Upstream source

**Library commit:** `9193b2eb7ce15faf8cf8b05ceb84f32befa9721a`
**Plus local rendering fix:** `explain_ranking()` returns list (not string)
  — from production commit `89ce2eef` (mobile rendering bug fix)

**Repository:** https://github.com/MadeByGFK/StackSift
**Source path:** `src/stacksift/`

## Vendored modules

| File | Upstream | Lines | Provides |
|------|----------|-------|----------|
| `analyzer.py` | `src/stacksift/analyzer.py` | 379 | `analyze_log_file` |
| `insights.py` | `src/stacksift/insights.py` | 328 | `build_timeline`, `determine_health`, `diagnostic_reasons`, `most_frequent_issue`, `sort_issues_by_severity` |
| `diagnostics.py` | `src/stacksift/diagnostics.py` | 787 | `rank_candidates`, `explain_ranking`, `build_incident_section`, `build_notable_events`, `_detect_degradation_window`, `group_evidence_by_family`, `classify_incident_section` |
| `parser.py` | `src/stacksift/parser.py` | 308 | `parse_log_line` (used by analyzer) |
| `scanner.py` | `src/stacksift/scanner.py` | 10 | `find_log_files` (used by analyzer) |
| `models.py` | `src/stacksift/models.py` | 9 | `LogEntry` (used by parser) |

**Total:** 1,821 lines

**Local divergence (issue #102, 2026-10-31):** `analyzer.py` gains an
opt-in `collect_comparison_evidence` parameter on `analyze_log_file`
(default OFF; when OFF the result shape is byte-identical to upstream).
This is a web-app-local addition, not an upstream change — do not
overwrite it on a vendor sync without re-applying the collector. The
SHASUMS entry for `analyzer.py` tracks this local version.

## Import rewriting

All `from stacksift.X import` statements have been rewritten to
`from app.vendor.X import`. The vendored modules are self-contained
and do not import from the pip-installed `stacksift` package.

## Verification

Each vendored file's SHA-256 is recorded in `SHASUMS.txt`.
To verify against upstream:
```bash
cd app/vendor
sha256sum -c SHASUMS.txt
# Note: diagnostics.py will differ from 9193b2eb due to the rendering fix.
# The local stacksift-lib/ copy is the authoritative source.
```

## Sync procedure

When the upstream library changes:
1. Copy updated files from `stacksift-lib/src/stacksift/` to `app/vendor/`
2. Re-run the sed rewrite for import statements
3. Update SHASUMS.txt
4. Run `python -m app.smoke_test`
5. Run full test suite and benchmarks
6. Document the new upstream commit in this file

## What is NOT vendored

- `cli.py` — command-line interface, not used by web app
- `reports.py` — report generation, not used by web app
- `redact.py` — already vendored separately as `app/redact.py`

## Removal of partial vendoring

The previous `app/diagnostics_vendor.py` (partial Phase D vendoring)
has been removed. `app/vendor/diagnostics.py` is now the single
authoritative implementation.
