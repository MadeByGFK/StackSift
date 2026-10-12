"""Deployment smoke test: verify all vendored imports resolve before serving traffic.

Run this as part of the build or as a startup check:
    python -m app.smoke_test

Exits 0 if all imports succeed, 1 with error message if any fail.
This catches missing vendored modules before they cause 500s in production.

Note: This test verifies the VENDORED modules (app.vendor.*), not the
pip-installed stacksift package. The web app must not depend on the
pip package for diagnostic functions (Railway pip cache issue).
"""

import sys


def main():
    errors = []

    # Vendored analyzer
    try:
        from app.vendor.analyzer import analyze_log_file
    except ImportError as e:
        errors.append(f"app.vendor.analyzer.analyze_log_file: {e}")

    # Vendored insights
    try:
        from app.vendor.insights import (
            build_timeline,
            determine_health,
            diagnostic_reasons,
            most_frequent_issue,
            sort_issues_by_severity,
        )
    except ImportError as e:
        errors.append(f"app.vendor.insights: {e}")

    # Vendored diagnostics - Phase C (ranking)
    try:
        from app.vendor.diagnostics import rank_candidates, explain_ranking
    except ImportError as e:
        errors.append(f"app.vendor.diagnostics (Phase C): {e}")

    # Vendored diagnostics - Phase D (incident section)
    try:
        from app.vendor.diagnostics import (
            build_incident_section,
            build_notable_events,
            _detect_degradation_window,
            group_evidence_by_family,
            classify_incident_section,
        )
    except ImportError as e:
        errors.append(f"app.vendor.diagnostics (Phase D): {e}")

    # Web app modules
    try:
        from app.redact import redact_secrets
    except ImportError as e:
        errors.append(f"app.redact: {e}")

    # Service (this will fail if any vendored import is broken)
    try:
        from app.service import analyze_upload
    except ImportError as e:
        errors.append(f"app.service: {e}")

    # Verify NO dependency on pip-installed stacksift for diagnostics
    # (The pip package may exist, but service.py must not import from it)
    import app.service as svc
    import inspect
    source = inspect.getsource(svc)
    if "from stacksift" in source or "import stacksift" in source:
        errors.append(
            "app.service still imports from 'stacksift' pip package! "
            "All diagnostic imports must use app.vendor.*"
        )

    if errors:
        print("SMOKE TEST FAILED:", file=sys.stderr)
        for err in errors:
            print(f"  ✗ {err}", file=sys.stderr)
        sys.exit(1)

    print("✓ All vendored imports resolve - safe to serve traffic")
    print("✓ No dependency on pip-installed stacksift for diagnostics")
    sys.exit(0)


if __name__ == "__main__":
    main()
