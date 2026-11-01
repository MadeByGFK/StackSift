"""Issue #103: batch analysis — unit/service coverage.

Pricing function, combined-payload assembly, bundle envelope, the
quota-claim admission helpers (both accounting systems), and the PDF
renderer. The HTTP + ledger journey lives in test_batch_paid_e2e.py;
PostgreSQL race coverage lives in test_batch_postgres_concurrency.py.
"""

import json
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import batch_admission as BA, credits as C, main, models as M
from app.batch_service import batch_severity, build_batch_payload
from app.db import Base
from app.pdf_export import generate_batch_pdf


# --- pricing (trim B1) -------------------------------------------------------

def test_obsolete_cost_batch_is_gone():
    assert not hasattr(C, "COST_BATCH")
    assert C.COST_BATCH_ADDITIONAL_FILE == 1


@pytest.mark.parametrize("n,free,total", [
    (2, True, 1), (2, False, 2),
    (3, True, 2), (3, False, 3),
    (4, True, 3), (4, False, 4),
    (5, True, 4), (5, False, 5),
])
def test_batch_total_cost_formula(n, free, total):
    assert C.batch_total_cost(n, free) == total


@pytest.mark.parametrize("n", [0, 1, 6])
def test_batch_total_cost_rejects_out_of_range(n):
    with pytest.raises(ValueError):
        C.batch_total_cost(n, True)


# --- combined payload assembly ------------------------------------------------

def _payload(filename, issues, *, total=10, levels=None, services=None,
             first="2024-01-01 10:00:00", last="2024-01-01 10:05:00"):
    return {
        "filename": filename,
        "detected_format": "text",
        "adapted": False,
        "results": {
            "file": filename, "total_lines": total, "parsed_lines": total,
            "malformed_lines": 1,
            "level_counts": levels or {"ERROR": 2},
            "service_counts": services or {"api": total},
            "issues": issues, "events": [],
            "first_seen": first, "last_seen": last,
        },
        "health": {"label": "Warning", "color": "yellow"},
        "sorted_issues": sorted(issues.items()),
        "top_issue": None, "diagnostic_issue": None,
        "diagnostic_explanation": None, "incident_section": {"type": "none"},
        "notable_events": [], "complexity_truncated": False,
        "complexity_notice": None, "timeline": [],
        "first_seen": first, "last_seen": last, "elapsed": 0.5,
    }


def _group(count, level="ERROR"):
    return {"level": level, "count": count, "services": ["api"]}


def test_build_payload_merges_by_exact_template_with_attribution():
    a = _payload("a.log", {"db failed": _group(10), "disk full": _group(3)},
                 total=20, levels={"ERROR": 13}, services={"api": 20})
    b = _payload("b.log", {"db failed": _group(5), "auth expired": _group(7, "WARN")},
                 total=30, levels={"ERROR": 5, "WARN": 7}, services={"api": 25, "web": 5},
                 first="2024-01-01 09:00:00", last="2024-01-01 11:00:00")
    payload = build_batch_payload(
        [(1, "a.log", a), (2, "b.log", b)],
        pricing={"file_count": 2, "first_file_cost": 0,
                 "additional_file_cost": 1, "total_cost": 1})
    assert payload["report_kind"] == "batch"
    assert payload["filename"] == "Batch \u2014 2 files"
    assert payload["summary"]["total_lines"] == 50
    assert payload["summary"]["malformed_lines"] == 2
    assert payload["summary"]["level_counts"] == {"ERROR": 18, "WARN": 7}
    assert payload["summary"]["service_counts"] == {"api": 45, "web": 5}
    assert payload["summary"]["first_seen"] == "2024-01-01 09:00:00"
    assert payload["summary"]["last_seen"] == "2024-01-01 11:00:00"
    assert payload["summary"]["unique_issue_patterns"] == 3
    combined = {e["template"]: e for e in payload["combined_issues"]}
    assert combined["db failed"]["count"] == 15
    assert combined["db failed"]["files"] == [
        {"ordinal": 1, "filename": "a.log", "count": 10, "level": "ERROR"},
        {"ordinal": 2, "filename": "b.log", "count": 5, "level": "ERROR"},
    ]
    # Per-file sections intact, in upload order; no cross-file verdict.
    assert [f["ordinal"] for f in payload["files"]] == [1, 2]
    assert payload["files"][0]["report"] is a
    assert "health" not in payload  # no fabricated combined health verdict
    assert "12 ERROR entries" not in payload["summary_sentence"]
    assert payload["summary_sentence"] == (
        "Across these 2 files, 18 ERROR entries and 0 CRITICAL entries were observed.")


def test_build_payload_identical_files_count_twice():
    a = _payload("same.log", {"db failed": _group(4)})
    payload = build_batch_payload(
        [(1, "same.log", a), (2, "same.log", a)],
        pricing={"file_count": 2, "first_file_cost": 1,
                 "additional_file_cost": 1, "total_cost": 2})
    assert payload["combined_issues"][0]["count"] == 8
    assert len(payload["combined_issues"][0]["files"]) == 2


def test_batch_severity_from_summed_levels():
    assert batch_severity({"ERROR": 1}) == "errors"
    assert batch_severity({"WARN": 2}) == "warnings"
    assert batch_severity({"INFO": 5}) == "ok"
    assert batch_severity({}) == "ok"


# --- quota-claim helpers on SQLite -------------------------------------------

@pytest.fixture
def batch_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'b.db'}",
                           connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _fk(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False)
    yield sessions
    engine.dispose()


def _user(db, email_addr="batch-unit@example.com"):
    user = M.User(email=email_addr, email_verified=True)
    db.add(user)
    db.flush()
    return user


def _seed_free(db, ip, n, *, minutes_ago=2, user_id=None):
    for _ in range(n):
        db.add(M.FreeRequest(
            request_id=uuid.uuid4().hex, user_id=user_id,
            anonymous_session_hash=None if user_id else "a" * 64,
            fingerprint="old",
            status="failed", quota_bucket_trusted_ip=ip,
            created_at=C._utcnow() - timedelta(minutes=minutes_ago),
            deadline=C._utcnow()))


def _seed_hits(db, ip, n, *, minutes_ago=2):
    for _ in range(n):
        db.add(M.RateLimitHit(trusted_ip=ip,
                              hit_at=C._utcnow() - timedelta(minutes=minutes_ago)))


IP = "198.51.100.7"


def test_quote_reads_both_accounting_systems(batch_db):
    with batch_db() as db:
        assert BA.free_first_available(db, IP) is True
        assert BA.batch_price(db, IP, 3) == (2, 0, True)
        _seed_free(db, IP, 10)
        db.commit()
        # Durable system exhausted -> no free first file.
        assert BA.free_first_available(db, IP) is False
        assert BA.batch_price(db, IP, 3) == (3, 1, False)
    with batch_db() as db:
        db.query(M.FreeRequest).delete()
        db.commit()
        _seed_hits(db, IP, 10)
        db.commit()
        # Shared-limiter system exhausted -> no free first file either.
        assert BA.free_first_available(db, IP) is False
    with batch_db() as db:
        # Quotation recorded nothing in either system.
        assert db.query(M.RateLimitHit).count() == 10  # only the seeds
        assert db.query(M.Operation).count() == 0


def test_admit_claims_both_systems_atomically(batch_db):
    with batch_db() as db:
        user = _user(db)
        C.grant_credits(db, user.id, "purchase", "unit-pack-1", 5)
        consent = C.create_consent(db, user.id, "batch", "h" * 64, 1)
        db.commit()
        op = BA.admit_batch_operation(db, user.id, "k1", "h" * 64, consent.id,
                                      "w1", IP, 2)
        db.commit()
        assert op.type == "batch" and op.cost == 1
        assert op.free_allowance_claim is True
        # Shared system: exactly one hit. Durable system: claim on the op.
        assert db.query(M.RateLimitHit).filter_by(trusted_ip=IP).count() == 1
        assert BA.durable_hourly_used(db, IP) == 1
        assert C.verify_account_invariants(db, user.id) == []
        C.release_operation(db, op.id, "w1", "test")
        db.commit()
        # B8: releasing the credits does NOT restore the free attempt.
        assert BA.durable_hourly_used(db, IP) == 1
        assert db.query(M.RateLimitHit).filter_by(trusted_ip=IP).count() == 1


def test_admit_insufficient_rolls_back_claim(batch_db):
    with batch_db() as db:
        user = _user(db)  # no grants at all
        consent = C.create_consent(db, user.id, "batch", "h" * 64, 1)
        db.commit()
        with pytest.raises(C.InsufficientCredits):
            BA.admit_batch_operation(db, user.id, "k1", "h" * 64, consent.id,
                                     "w1", IP, 2)
        db.rollback()
        assert db.query(M.RateLimitHit).count() == 0
        assert db.query(M.Operation).count() == 0


def test_admit_requotes_when_allowance_consumed(batch_db):
    with batch_db() as db:
        user = _user(db)
        C.grant_credits(db, user.id, "purchase", "unit-pack-2", 5)
        # Consent quoted at the free-first total for N=2 (1 credit)...
        consent = C.create_consent(db, user.id, "batch", "h" * 64, 1)
        db.commit()
        # ...but the allowance is exhausted by confirm time.
        _seed_free(db, IP, 10)
        db.commit()
        with pytest.raises(BA.RequoteRequired) as excinfo:
            BA.admit_batch_operation(db, user.id, "k1", "h" * 64, consent.id,
                                     "w1", IP, 2)
        db.rollback()
        assert excinfo.value.new_total == 2
        assert excinfo.value.new_first_cost == 1
        assert db.query(M.Operation).count() == 0
        assert db.query(M.RateLimitHit).count() == 0


def test_batch_claim_blocks_single_route_at_ten(batch_db):
    """The alternating-route bypass: 9 free singles + 1 batch claim = 10,
    so the next single-file admission gets the paid offer, not a free run."""
    from app import analysis_admission as A
    with batch_db() as db:
        user = _user(db)
        C.grant_credits(db, user.id, "purchase", "unit-pack-3", 5)
        _seed_free(db, IP, 9, user_id=user.id)
        consent = C.create_consent(db, user.id, "batch", "h" * 64, 1)
        db.commit()
        op = BA.admit_batch_operation(db, user.id, "k1", "h" * 64, consent.id,
                                      "w1", IP, 2)
        db.commit()
        assert op.free_allowance_claim is True
        item, created = A.admit(db, user.id, None, "single-key-1", "d" * 64,
                                IP, "w2")
        db.rollback()
        assert item is None and created is False  # paid offer path, not free


# --- bundle envelope -----------------------------------------------------------

def test_bundle_envelope_roundtrip_preserves_order(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "_PAID_PENDING_DIR", str(tmp_path / "pending"))
    files = [(1, "a.log", b"first\n"), (2, "a.log", b"second\n"), (3, "b.txt", b"third\n")]
    counts = [(6, 1), (7, 1), (6, 1)]
    cid = str(uuid.uuid4())
    main._store_batch_pending(cid, files, counts)
    loaded = main._load_batch_pending(cid)
    assert loaded == [(1, "a.log", b"first\n", 6, 1),
                      (2, "a.log", b"second\n", 7, 1),
                      (3, "b.txt", b"third\n", 6, 1)]
    assert main._batch_bundle_hash(files) == main._batch_bundle_hash(list(files))
    reordered = [files[1], files[0], files[2]]
    reordered = [(i + 1, f, c) for i, (_, f, c) in enumerate(reordered)]
    assert main._batch_bundle_hash(reordered) != main._batch_bundle_hash(files)


# --- PDF: per-file MAX_ISSUES disclosure (trim B5) ------------------------------

def test_batch_pdf_discloses_per_file_omissions_and_keeps_sections():
    big_issues = [(f"pattern {i} failed", {"level": "ERROR", "count": 1})
                  for i in range(105)]
    small = _payload("small.log", {"rare failure": _group(2)})
    big = _payload("big.log", {})
    big["sorted_issues"] = big_issues
    big["results"]["issues"] = {t: d for t, d in big_issues}
    payload = build_batch_payload(
        [(1, "big.log", big), (2, "small.log", small)],
        pricing={"file_count": 2, "first_file_cost": 0,
                 "additional_file_cost": 1, "total_cost": 1})
    # build_batch_payload derives sorted sections from the per-file
    # payloads as stored; emulate the stored JSON shape for section 1.
    payload["files"][0]["report"]["sorted_issues"] = big_issues
    pdf = generate_batch_pdf(json.dumps(payload, default=str), payload["filename"])
    assert pdf.startswith(b"%PDF")
    assert b"more issue patterns in this file not shown" in pdf
    assert b"rare failure" in pdf  # second section NOT silently omitted
    assert b"File 2: small.log" in pdf


# --- Per-file diagnostic context rendering (Codex P2 on PR #114) ----------
# The combined artifacts must render the per-file diagnostic explanation
# and timeline retained in the payload, like the single-file report does;
# reducing each file to its headline + issue counts loses paid context.

def _context_payload():
    a = _payload("a.log", {"db failed": _group(10)})
    a["diagnostic_issue"] = ("db failed", {"level": "ERROR", "count": 10})
    a["diagnostic_explanation"] = [
        "Errors cluster in a single burst", "First seen at startup"]
    a["timeline"] = [
        {"label": "10:00", "warn": 1, "error": 4, "critical": 0, "total": 5},
        {"label": "10:05", "warn": 0, "error": 6, "critical": 1, "total": 7},
    ]
    b = _payload("b.log", {"auth expired": _group(7, "WARN")})
    return build_batch_payload(
        [(1, "a.log", a), (2, "b.log", b)],
        pricing={"file_count": 2, "first_file_cost": 0,
                 "additional_file_cost": 1, "total_cost": 1})


def test_batch_pdf_renders_per_file_diagnostic_context():
    payload = _context_payload()
    pdf = generate_batch_pdf(json.dumps(payload, default=str), payload["filename"])
    assert pdf.startswith(b"%PDF")
    assert b"Errors cluster in a single burst" in pdf
    assert b"Investigate first: [ERROR] db failed" in pdf
    assert b"Timeline: warnings + errors per 5 min" in pdf
    assert b"10:05: 1 critical, 6 errors, 0 warnings" in pdf


def test_batch_html_renders_per_file_diagnostic_context():
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    templates_dir = Path(__file__).parents[1] / "app" / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)),
                      autoescape=select_autoescape(["html"]))
    payload = _context_payload()
    html = env.get_template("batch_report.html").render(
        filename=payload["filename"],
        summary_sentence=payload["summary_sentence"],
        summary=payload["summary"],
        combined_issues=payload["combined_issues"],
        files=payload["files"],
        current_user=None, report_id=None, csrf_token="")
    assert "Errors cluster in a single burst" in html
    assert "First seen at startup" in html
    assert "Incident timeline" in html
    assert "10:05" in html
