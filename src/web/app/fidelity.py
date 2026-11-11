"""Issue #170 fidelity slice: display projections for ruled CALL items.

Pure helpers only — no charging, no pipeline behaviour. Every value
here is projected from data the analysis already retains:

- SS-format report ID (S1-C2): ``SS-<analysis date YYYYMMDD>-<4-digit
  suffix>``, generated at store time (see credits.assign_ss_id),
  stored on the Result row, stable and unique per report. Legacy rows
  without a stored value derive deterministically from the row's
  ready_at date + UUID, so the display is stable across renders.
- Honest format label (S1-C1 format half, as ruled): the detector
  distinguishes plain-text vs JSON-lines ONLY — surfaces show exactly
  that, never a finer taxonomy.
- Timeline caption (S1-C4): templated derivation from bucket data
  only (peak window, counts, span). No free prose.
- Observed log excerpts (S1-C3): projected from the retained
  diagnostic evidence (already redacted at capture) and passed
  through the existing redaction pass AGAIN before display; if
  redaction is unavailable or fails, NO excerpt is projected.
"""

from __future__ import annotations

from datetime import datetime, timezone


def format_ss_id(on, suffix: int) -> str:
    return f"SS-{on.strftime('%Y%m%d')}-{int(suffix):04d}"


def derive_ss_id(result_id, ready_at) -> str | None:
    """Deterministic legacy fallback: date from ready_at, suffix from
    the UUID integer. Stable for a given row; uniqueness for legacy
    rows is best-effort (stored values, assigned at store time, are
    sequence-guaranteed)."""
    if result_id is None or ready_at is None:
        return None
    try:
        import uuid as _uuid
        suffix = _uuid.UUID(str(result_id)).int % 10000
    except (ValueError, AttributeError, TypeError):
        return None
    when = ready_at
    if isinstance(when, str):
        try:
            when = datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError:
            return None
    return format_ss_id(when, suffix)


def honest_format_label(detected_format) -> str:
    return "JSON-lines" if detected_format == "jsonlines" else "Plain-text"


def analysis_timestamp_label(value) -> str | None:
    """'Nov 10, 2026 · 14:32 UTC' from a datetime or ISO string."""
    if value is None:
        return None
    when = value
    if isinstance(when, str):
        try:
            when = datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(when, datetime):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%b %d, %Y · %H:%M UTC")


def timeline_caption(timeline) -> str | None:
    """S1-C4: templated caption from bucket data only.

    Statements: total warnings+errors, the peak bucket (label +
    count), and the first/last bucket labels (the span). Nothing
    else is claimed.
    """
    if not timeline or len(timeline) < 2:
        return None
    totals = []
    for b in timeline:
        try:
            totals.append(int(b.get("warn", 0)) + int(b.get("error", 0))
                          + int(b.get("critical", 0)))
        except (AttributeError, TypeError, ValueError):
            return None
    total = sum(totals)
    if total <= 0:
        return None
    peak = max(totals)
    peak_label = timeline[totals.index(peak)].get("label")
    first_label = timeline[0].get("label")
    last_label = timeline[-1].get("label")
    if not (peak_label and first_label and last_label):
        return None
    return (f"{total} warnings + errors across the window "
            f"{first_label}–{last_label} UTC; peak of {peak} at "
            f"{peak_label}.")


def observed_excerpts(results, observed_templates) -> dict:
    """S1-C3: {template: [excerpt, ...]} for Observed-group templates.

    Source: retained diagnostic evidence groups (redacted at
    capture). Each text passes the existing redaction pass again;
    ANY failure yields no excerpts at all (fail closed).
    """
    if not isinstance(results, dict) or not observed_templates:
        return {}
    evidence = results.get("diagnostic_evidence")
    if not isinstance(evidence, dict):
        return {}
    groups = evidence.get("groups")
    if not isinstance(groups, dict):
        return {}
    try:
        from app.redact import redact_secrets
    except Exception:
        return {}
    out = {}
    try:
        for template in observed_templates:
            group = groups.get(template)
            if not isinstance(group, dict):
                continue
            texts = []
            for excerpt in group.get("excerpts") or []:
                if isinstance(excerpt, dict) and excerpt.get("text"):
                    texts.append({
                        "text": redact_secrets(str(excerpt["text"])),
                        "analysis_line_number":
                            excerpt.get("analysis_line_number"),
                    })
            if texts:
                out[template] = texts[:2]
    except Exception:
        return {}
    return out
