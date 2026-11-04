"""Issue #107: report access — retention/share capability helpers.

Owns the pieces the routes in main.py share:

- the isolated public-limiter key namespace (``s:`` + first 40 hex of
  SHA-256(IP) = 42 chars, fitting RateLimitBucket.trusted_ip String(45),
  IPv6 included);
- token format validation and the hash-only capability lookup with the
  identical-404 discipline (every failure mode returns None here; the
  route renders one generic response);
- the allowlisted single-file report-kind gate (T4: compare/batch are
  rejected before link creation and never rendered publicly);
- paid-PDF provenance lookup for T3 (a PDF is shareable only when a
  paid, unexpired PDF Result exists for the report);
- ``/s/*`` token-path log redaction (draft §6 launch requirement).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re

from sqlalchemy import select

from app import auth, credits, models

TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SHARE_PATH_PATTERN = re.compile(r"/s/[0-9a-f]{64}")

# Issue #135: the formats a share link can serve. TXT is free; the
# other three require the report's #129 export unlock at creation.
SHARE_FORMATS = ("pdf", "txt", "json", "csv")
GATED_SHARE_FORMATS = ("pdf", "json", "csv")
DEFAULT_SHARE_FORMAT = "txt"


def normalize_share_format(value) -> str | None:
    """Canonical share format for a request value, or None if invalid.

    A missing/empty value defaults to txt (the free text share, and
    the format pre-#135 clients created implicitly)."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return DEFAULT_SHARE_FORMAT
    if not isinstance(value, str):
        return None
    fmt = value.strip().lower()
    return fmt if fmt in SHARE_FORMATS else None


def share_format_of(sharing) -> str:
    """The format a sharing row serves; NULL (pre-#135) reads as txt."""
    fmt = getattr(sharing, "share_format", None)
    return fmt if fmt in SHARE_FORMATS else DEFAULT_SHARE_FORMAT


def share_limit_key(ip: str) -> str:
    """Isolated limiter key for public share traffic (draft §7)."""
    digest = hashlib.sha256(str(ip).encode("utf-8")).hexdigest()
    return "s:" + digest[:40]


def is_single_file_payload(payload) -> bool:
    """True only for the verified single-file report shape (T4).

    Mirrors structured_export.check_report_kind: no discriminator, or an
    explicit single/analysis one, is single-file; compare/batch/unknown
    discriminators fail closed.
    """
    if not isinstance(payload, dict):
        return False
    kind = payload.get("report_kind")
    return kind is None or kind in ("single", "analysis")


def lookup_shared(db, raw_token: str):
    """Resolve a raw share token to (sharing, result, payload) or None.

    EVERY failure — malformed, unknown, revoked, rotated away, source
    expired/deleted/corrupt, kind not shareable — returns None so the
    caller renders the one identical 404 (draft §6). The owner identity
    used for result_payload comes from the trusted sharing row, never
    from the requester, and is never exposed to the template.
    """
    if not isinstance(raw_token, str) or not TOKEN_PATTERN.match(raw_token):
        return None
    token_hash = auth.hash_token(raw_token)
    sharing = db.execute(
        select(models.ReportSharing).where(
            models.ReportSharing.token_hash == token_hash)
    ).scalar_one_or_none()
    if sharing is None or sharing.revoked_at is not None:
        return None
    result = db.get(models.Result, sharing.result_id)
    if result is None:
        return None
    if result.user_id != sharing.owner_user_id or result.type != "analysis":
        return None
    if result.deleted_at is not None:
        return None
    try:
        payload = credits.result_payload(
            result, user_id=result.user_id,
            operation_id=result.operation_id,
            free_request_id=result.free_request_id,
        )
    except credits.AdmissionError:
        return None
    if not is_single_file_payload(payload):
        return None
    return sharing, result, payload


def is_export_unlocked(db, source_result) -> bool:
    """Issue #129 §5: an export-unlocked report counts as having its
    PDF export purchased for the share-link PDF rule — the unlock may
    have been bought with a CSV or JSON first generation, in which
    case no PDF operation exists at all."""
    return credits.is_export_unlocked(
        db, source_result.user_id, source_result.id)


def has_pdf_export_operation(db, source_result) -> bool:
    """True when a completed PDF operation exists for the report, even
    if its artifact has since expired. Issue #107 T6 still governs
    that case (an expired PDF is not shareable); the #129 on-the-fly
    generation in the share route applies only when no PDF was ever
    generated but the report is export-unlocked via another format."""
    ops = db.execute(
        select(models.Operation).where(
            models.Operation.user_id == source_result.user_id,
            models.Operation.type == "pdf",
            models.Operation.status == "completed",
        )
    ).scalars().all()
    # Canonical-tolerant matching (PR #132 follow-up): a legacy PDF
    # operation stored under an uppercase or unhyphenated key counts
    # exactly like the canonical pdf-{id} key. The query above already
    # filters type == "pdf", so export_key_belongs_to's structured-*
    # branch can never match here — only its pdf-* branch applies.
    return any(
        credits.export_key_belongs_to(op.idempotency_key, source_result.id)
        for op in ops)


def find_shareable_pdf(db, source_result):
    """Return (pdf_result, pdf_bytes) for a paid unexpired PDF, else None.

    T3 provenance: PDF exports are Operations of type "pdf" whose
    idempotency key belongs to the source under
    credits.export_key_belongs_to — canonically ``pdf-{source_id}``
    (plus server retry suffixes), tolerating legacy noncanonical
    stored forms. The PDF Result is validated with its OWN expiry/integrity via
    result_payload — extending the source never extends it (T6).
    """
    import base64 as _b64

    ops = db.execute(
        select(models.Operation).where(
            models.Operation.user_id == source_result.user_id,
            models.Operation.type == "pdf",
            models.Operation.status == "completed",
            models.Operation.result_id.isnot(None),
        )
    ).scalars().all()
    # Canonical-tolerant matching, as in has_pdf_export_operation
    # above: legacy uppercase/unhyphenated pdf-* keys (including
    # -retry- suffixes, which export_key_belongs_to handles) belong
    # to this report. The type == "pdf" filter above scopes the
    # helper to pdf operations only.
    candidates = [
        op for op in ops
        if credits.export_key_belongs_to(op.idempotency_key, source_result.id)
    ]
    if not candidates:
        return None
    latest = max(candidates, key=lambda op: (op.created_at, str(op.id)))
    pdf_result = db.get(models.Result, latest.result_id)
    if pdf_result is None or pdf_result.type != "pdf" or pdf_result.deleted_at is not None:
        return None
    try:
        manifest = credits.result_payload(
            pdf_result, user_id=source_result.user_id, operation_id=latest.id)
        pdf_bytes = _b64.b64decode(manifest["pdf_base64"], validate=True)
    except Exception:
        return None
    if not pdf_bytes.startswith(b"%PDF"):
        return None
    return pdf_result, pdf_bytes


def public_projection(payload: dict) -> dict:
    """Allowlisted display projection for shared_report.html (draft §6).

    Only report body data crosses to the public template: no DB objects,
    no current_user/csrf, no report id or account metadata.
    """
    keys = (
        "filename", "elapsed", "detected_format", "health",
        "results", "sorted_issues", "top_issue", "diagnostic_issue",
        "diagnostic_explanation", "timeline", "first_seen", "last_seen",
        "complexity_truncated", "complexity_notice", "adapted",
    )
    projection = {k: payload.get(k) for k in keys}
    projection.setdefault("elapsed", 0.0)
    if not isinstance(projection.get("results"), dict):
        projection["results"] = {}
    if not isinstance(projection.get("sorted_issues"), list):
        projection["sorted_issues"] = []
    return projection


class SharePathRedactionFilter(logging.Filter):
    """Redact raw share tokens from log records (draft §6).

    Uvicorn/edge access logs would otherwise persist the bearer token
    from the request path. This filter rewrites the rendered message
    of any record passing through it; attach it to the access/app
    loggers (main.py does). Edge/CDN log configuration remains a
    deployment verification item (see RETENTION_SHARING.md).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Uvicorn access records (PR #128 round 2, Finding 3): the
        # record carries a 5-tuple of args — (client_addr, method,
        # full_path, http_version, status_code) — and Uvicorn's
        # AccessFormatter.formatMessage unpacks exactly five values.
        # Clearing args (the old behaviour) raised ValueError for
        # every /s/* request. Redact the token ONLY inside the
        # full_path argument (index 2) and preserve the tuple shape.
        try:
            args = record.args
            if isinstance(args, tuple) and len(args) == 5:
                new_args = tuple(
                    _SHARE_PATH_PATTERN.sub("/s/[redacted]", a)
                    if isinstance(a, str) else a
                    for a in args
                )
                if new_args != args:
                    record.args = new_args
                return True
        except Exception:
            return True
        # Fallback for non-Uvicorn records (app/uvicorn.error loggers,
        # already-rendered or non-standard args): redact the rendered
        # message and flatten it, which is safe for the standard
        # Formatter used by those loggers.
        try:
            message = record.getMessage()
        except Exception:
            return True
        if "/s/" in message:
            redacted = _SHARE_PATH_PATTERN.sub("/s/[redacted]", message)
            if redacted != message:
                record.msg = redacted
                record.args = ()
        return True


def action_request_hash(source_result, action_kind: str,
                        share_format: str | None = None) -> str:
    """Canonical request hash binding an action to the source snapshot.

    Issue #135: share actions also bind the link format, so replaying
    a create key with a DIFFERENT format is a key-reuse conflict
    (409), never a silent second link under the same key."""
    return credits.hash_input(json.dumps(
        {
            "action_kind": action_kind,
            "source_result_id": str(source_result.id),
            "source_integrity_digest": source_result.integrity_digest,
            "unit_days": credits.RETENTION_EXTENSION_DAYS
            if action_kind == "retention_extension" else None,
            "share_format": share_format,
            "version": 1,
        },
        sort_keys=True, separators=(",", ":"),
    ).encode())
