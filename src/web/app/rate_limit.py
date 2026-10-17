"""Sliding-window rate limiters for the StackSift free tier.

Two implementations:

- ``RateLimiter`` — in-memory, per-process. Kept for the no-database demo
  path only. Do NOT use it when traffic is served by multiple processes;
  each process enforces the limit against only its own fraction of traffic
  (see files/staging-rate-limit-root-cause.md).
- ``PostgresRateLimiter`` — shared, atomic enforcement backed by
  PostgreSQL. One row per admitted analysis in ``rate_limit_hits``;
  admissions for the same client IP are serialized on a per-IP bucket row
  (``rate_limit_buckets``), so concurrent workers and replicas share the
  same counts. Database failures fail closed (``RateLimitUnavailable``) —
  they never silently disable the limits.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        return True

    def check(self, key: str) -> bool:
        """Check without recording. For atomic multi-limiter checks."""
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        return len(hits) < self.max_requests

    def record(self, key: str) -> None:
        """Record a hit. Call only after check() passes."""
        self._hits[key].append(time.monotonic())

    def remaining(self, key: str) -> int:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()
        return max(0, self.max_requests - len(hits))


class BurstLimited(Exception):
    """Raised when the short-window (burst) limit is exceeded."""


class HourlyLimited(Exception):
    """Raised when the hourly limit is exceeded."""


class RateLimitUnavailable(Exception):
    """Raised when the limiter cannot reach the database.

    Callers must treat this as fail-closed (e.g. HTTP 503), never as
    permission to skip rate limiting.
    """


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PostgresRateLimiter:
    """Atomic, cross-process rate limiter backed by PostgreSQL.

    A single admitted analysis counts toward both the burst window and the
    hourly window. Admission for one client IP is serialized on that IP's
    bucket row (upsert-then-``SELECT ... FOR UPDATE``, the same pattern as
    ``FreeBucket``/``CapacityScope``), so any number of workers or replicas
    share one consistent count.

    ``admit()`` manages its own transaction: it starts with a rollback so
    any autobegun read transaction is closed, and commits on success.
    Call it before any other database writes in the request.
    """

    def __init__(
        self,
        burst_max: int = 2,
        burst_window: int = 60,
        hourly_max: int = 10,
        hourly_window: int = 3600,
    ):
        self.burst_max = burst_max
        self.burst_window = burst_window
        self.hourly_max = hourly_max
        self.hourly_window = hourly_window
        # Per-process throttle for the opportunistic expired-row sweep.
        self._last_sweep = datetime.min.replace(tzinfo=timezone.utc)

    # -- public API --------------------------------------------------------

    def admit(self, db, ip: str, request_id: str | None = None) -> str:
        """Admit one analysis for ``ip``.

        Returns ``'ok'`` when the analysis is admitted and recorded, or
        ``'replay'`` when ``request_id`` identifies an already-completed
        request from the same IP — replays never consume quota.

        Raises ``BurstLimited`` / ``HourlyLimited`` when a limit is hit and
        ``RateLimitUnavailable`` when the database cannot be reached (the
        caller must fail closed, e.g. HTTP 503).
        """
        from app import models as M

        db.rollback()  # close any autobegun read transaction; start clean
        try:
            if request_id and self._is_completed_replay(db, ip, request_id):
                db.rollback()
                return "replay"
            db.rollback()  # end the probe's read transaction
        except SQLAlchemyError:
            # The idempotency probe must never fail the request. If we
            # cannot check (e.g. free_requests absent pre-PR #17), treat
            # the request as new; the limits below still apply.
            db.rollback()

        try:
            self._lock_bucket(db, ip, M)
            now = _utcnow()
            self._delete_expired(db, ip, now, M)
            burst_hits = self._count_since(db, ip, now, self.burst_window, M)
            if burst_hits >= self.burst_max:
                db.rollback()
                raise BurstLimited(f"burst limit reached for {ip}")
            hourly_hits = self._count_since(db, ip, now, self.hourly_window, M)
            if hourly_hits >= self.hourly_max:
                db.rollback()
                raise HourlyLimited(f"hourly limit reached for {ip}")
            db.add(M.RateLimitHit(trusted_ip=ip, hit_at=now))
            self._maybe_sweep(db, now, M)
            db.commit()
            return "ok"
        except (BurstLimited, HourlyLimited):
            raise
        except SQLAlchemyError as exc:
            db.rollback()
            raise RateLimitUnavailable("rate-limit database unavailable") from exc

    def remaining(self, db, ip: str) -> int:
        """Hourly quota remaining for ``ip``. Fail-closed: 0 on DB errors."""
        from app import models as M

        try:
            db.rollback()
            now = _utcnow()
            hits = self._count_since(db, ip, now, self.hourly_window, M)
            db.rollback()
            return max(0, self.hourly_max - hits)
        except SQLAlchemyError:
            db.rollback()
            return 0

    # -- internals ---------------------------------------------------------

    def _is_completed_replay(self, db, ip: str, request_id: str) -> bool:
        """True when ``request_id`` is an already-completed request from ``ip``.

        Uses raw SQL so the limiter does not depend on PR #17's models: if
        ``free_requests`` is absent the query raises, the caller degrades to
        treating the request as new, and the limits still apply.
        """
        row = db.execute(
            text(
                "SELECT status, quota_bucket_trusted_ip FROM free_requests "
                "WHERE request_id = :rid"
            ),
            {"rid": request_id},
        ).first()
        if row is None:
            return False
        status, bucket_ip = row[0], row[1]
        return status == "completed" and bucket_ip == ip

    def _lock_bucket(self, db, ip: str, M) -> None:
        """Upsert the per-IP bucket row, then lock it for this transaction."""
        if db.bind.dialect.name == "postgresql":
            upsert = pg_insert(M.RateLimitBucket).values(trusted_ip=ip)
        else:
            upsert = sqlite_insert(M.RateLimitBucket).values(trusted_ip=ip)
        db.execute(upsert.on_conflict_do_nothing(index_elements=["trusted_ip"]))
        db.flush()
        db.execute(
            select(M.RateLimitBucket)
            .where(M.RateLimitBucket.trusted_ip == ip)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()

    def _delete_expired(self, db, ip: str, now: datetime, M) -> None:
        db.execute(
            delete(M.RateLimitHit).where(
                M.RateLimitHit.trusted_ip == ip,
                M.RateLimitHit.hit_at < now - timedelta(seconds=self.hourly_window),
            )
        )

    def _count_since(self, db, ip: str, now: datetime, window: int, M) -> int:
        return (
            db.scalar(
                select(func.count())
                .select_from(M.RateLimitHit)
                .where(
                    M.RateLimitHit.trusted_ip == ip,
                    M.RateLimitHit.hit_at > now - timedelta(seconds=window),
                )
            )
            or 0
        )

    def _maybe_sweep(self, db, now: datetime, M) -> None:
        """Opportunistically delete expired rows for cold IPs (hourly)."""
        if now - self._last_sweep < timedelta(hours=1):
            return
        self._last_sweep = now
        db.execute(
            delete(M.RateLimitHit).where(
                M.RateLimitHit.hit_at < now - timedelta(seconds=self.hourly_window)
            )
        )
